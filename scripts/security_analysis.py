"""Security analysis: runs explicit attack scenarios against the REAL application and records what happened.

    python scripts/security_analysis.py              # uses the 'evidence_test' database (emptied on every run)
    python scripts/security_analysis.py --db my_test_db

Writes report/security_results.json (shown in the web UI under "Security analysis") and prints a table.
Exit status is 1 if any scenario failed, so it can run in CI.
"""
import argparse, datetime, hashlib, json, math, os, platform, socket, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _demo_env import DemoWorld, ROOT, E                       # noqa: E402
from client.api import EvidenceClient, ApiError                # noqa: E402
import requests                                                # noqa: E402

SCENARIOS = []


def scenario(category, title, expected):
    def deco(fn):
        SCENARIOS.append((category, title, expected, fn))
        return fn
    return deco


# ---------------------------------------------------------------- helpers
def entropy(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def status(fn):
    """Run fn; return (http_status_or_None, message)."""
    try:
        fn()
        return None, "request was accepted"
    except ApiError as e:
        return e.status, e.msg


def new_transfer(w, who="alice", to="bob", data=None, name="statement.txt"):
    data = data if data is not None else os.urandom(4096)
    return w.client(who).send(w.priv[who], to, data, name)["id"], data


def fetch(w, tid, who="bob"):
    c = w.client(who)
    return c._req("GET", f"/api/transfers/{tid}").json(), c._req("GET", f"/api/transfers/{tid}/ciphertext").content


def rejects(fn, needle):
    """fn must raise IntegrityError whose message contains `needle`."""
    try:
        fn()
        return False, "ACCEPTED: the modification was not detected"
    except E.IntegrityError as e:
        return needle.lower() in str(e).lower(), str(e)


def flip(b, i):
    c = bytearray(b)
    c[i] ^= 1
    return bytes(c)


def stored_path(w, tid):
    return os.path.join(w.storage_dir, tid + ".bin")


def audit_actions(w):
    return [r["action"] for r in w.db("SELECT action FROM audit_log ORDER BY id")]


# ================================================================= CONFIDENTIALITY
MARK = b"CONFIDENTIAL-WITNESS-7731"


@scenario("Confidentiality", "Server storage holds no plaintext", "No readable content; ciphertext looks random")
def _(w):
    data = (MARK + b" Statement of the witness regarding the events of the evening. ") * 1500
    tid, _ = new_transfer(w, data=data, name="witness.txt")
    stored = open(stored_path(w, tid), "rb").read()
    ent = entropy(stored)
    return (MARK not in stored and b"Statement" not in stored and ent > 7.9,
            f"marker present in stored file: {MARK in stored}; entropy {ent:.3f} bits/byte (plaintext {entropy(data):.2f})")


@scenario("Confidentiality", "Same file sent twice gives unrelated ciphertext", "Fresh key and IV per transfer")
def _(w):
    data = b"identical evidence content " * 2000
    t1, _ = new_transfer(w, data=data)
    t2, _ = new_transfer(w, data=data)
    b1, b2 = (open(stored_path(w, t), "rb").read() for t in (t1, t2))
    n = min(len(b1), len(b2)) - 52
    same = sum(x == y for x, y in zip(b1[20:20 + n], b2[20:20 + n])) / n
    return b1 != b2 and same < 0.02, f"{same * 100:.2f}% of ciphertext bytes coincide (chance level is 0.39%)"


@scenario("Confidentiality", "A different private key cannot recover the file key", "RSA-OAEP unwrap fails")
def _(w):
    tid, _ = new_transfer(w)
    meta, blob = fetch(w, tid)
    ok1, m1 = rejects(lambda: EvidenceClient.open_envelope(meta, blob, w.priv["carol"]), "not the key")
    import base64
    ok2, m2 = rejects(lambda: E.unwrap_key(w.priv["carol"], base64.b64decode(meta["wrapped_key"])), "not encrypted for your key")
    return ok1 and ok2, f"client check: '{m1}'; raw OAEP unwrap: '{m2}'"


# ================================================================= INTEGRITY
def _tamper(w, mutate, needle, bypass_hash=False):
    import base64
    tid, _ = new_transfer(w)
    meta, blob = fetch(w, tid)
    bad = mutate(blob)
    if bypass_hash:
        keymat = E.unwrap_key(w.priv["bob"], base64.b64decode(meta["wrapped_key"]))
        return rejects(lambda: E.decrypt(bad, keymat), needle)
    return rejects(lambda: EvidenceClient.open_envelope(meta, bad, w.priv["bob"]), needle)


@scenario("Integrity", "One bit flipped in the ciphertext (hash check)", "Ciphertext SHA-256 mismatch")
def _(w): return _tamper(w, lambda b: flip(b, 30), "hash")


@scenario("Integrity", "One bit flipped, hash check bypassed (MAC check)", "HMAC-SHA256 fails before decryption")
def _(w): return _tamper(w, lambda b: flip(b, 30), "MAC verification failed", True)


@scenario("Integrity", "IV modified", "HMAC covers the IV")
def _(w): return _tamper(w, lambda b: flip(b, 6), "MAC verification failed", True)


@scenario("Integrity", "MAC tag modified", "Tag comparison fails")
def _(w): return _tamper(w, lambda b: flip(b, len(b) - 1), "MAC verification failed", True)


@scenario("Integrity", "Ciphertext truncated by three blocks", "Rejected as malformed or by the MAC")
def _(w):
    ok, msg = _tamper(w, lambda b: b[:-48], "", True)
    return ok and ("MAC" in msg or "malformed" in msg), msg


@scenario("Integrity", "Ciphertext swapped for another valid ciphertext", "Hash mismatch; MAC fails under the right key")
def _(w):
    import base64
    t1, _ = new_transfer(w)
    t2, _ = new_transfer(w)
    meta1, _ = fetch(w, t1)
    _, blob2 = fetch(w, t2)
    ok1, m1 = rejects(lambda: EvidenceClient.open_envelope(meta1, blob2, w.priv["bob"]), "hash")
    keymat1 = E.unwrap_key(w.priv["bob"], base64.b64decode(meta1["wrapped_key"]))
    ok2, m2 = rejects(lambda: E.decrypt(blob2, keymat1), "MAC verification failed")
    return ok1 and ok2, f"hash check: '{m1}'; MAC under original key: '{m2}'"


@scenario("Integrity", "Stored file altered on the server's disk", "Server refuses to serve it and audits the event")
def _(w):
    tid, _ = new_transfer(w)
    p = stored_path(w, tid)
    raw = open(p, "rb").read()
    open(p, "wb").write(flip(raw, 40))
    st, msg = status(lambda: fetch(w, tid))
    audited = "STORAGE_TAMPER_DETECTED" in audit_actions(w)
    return st == 500 and audited, f"HTTP {st} '{msg}'; audit entry STORAGE_TAMPER_DETECTED recorded: {audited}"


# ================================================================= AUTHENTICITY / NON-REPUDIATION
@scenario("Authenticity", "Signature forged with another officer's key", "Upload rejected: signature invalid")
def _(w):
    alice = w.client("alice")
    form, blob = alice.build_transfer(w.priv["mallory"], "bob", b"forged evidence", "forged.txt")
    st, msg = status(lambda: alice.post_transfer(form, blob))
    return st == 400 and "signature" in msg, f"HTTP {st}: {msg}"


@scenario("Authenticity", "Any signed field changed after signing", "Every variant rejected (filename, type, size, recipient)")
def _(w):
    alice = w.client("alice")
    carol_fp = next(r["fingerprint"] for r in alice.recipients() if r["username"] == "carol")
    results = []
    for field, value in (("filename", "other.txt"), ("mime_type", "application/x-evil"), ("size", "1"),
                         ("recipient", "carol")):
        form, blob = alice.build_transfer(w.priv["alice"], "bob", b"signed content " * 50, "signed.txt")
        form[field] = value
        if field == "recipient":
            form["recipient_key_fp"] = carol_fp
        results.append((field, status(lambda: alice.post_transfer(form, blob))[0]))
    return all(s == 400 for _, s in results), ", ".join(f"{f}→HTTP {s}" for f, s in results)


@scenario("Authenticity", "Registering a key without proof of possession", "Rejected")
def _(w):
    import base64
    alice = w.client("alice")
    bob_pub = E.pub_pem(w.priv["bob"])
    fp = E.fingerprint(w.priv["bob"].public_key())
    sig = base64.b64encode(E.sign(w.priv["alice"], E.pop_message("alice", fp))).decode()
    st, msg = status(lambda: alice._req("PUT", "/api/me/key", json={"public_key_pem": bob_pub, "pop_signature": sig}))
    return st == 400, f"HTTP {st}: {msg}"


@scenario("Authenticity", "Retired key can no longer sign uploads", "Old key rejected after rotation")
def _(w):
    mal = w.client("mallory")
    old = w.priv["mallory"]
    new = E.generate_rsa()
    mal.register_key(new)
    w.priv["mallory"] = new
    form, blob = mal.build_transfer(old, "bob", b"signed with the retired key", "old.txt")
    st, msg = status(lambda: mal.post_transfer(form, blob))
    return st == 400, f"HTTP {st}: {msg}"


# ================================================================= AUTHORIZATION
def _denied(w, who):
    tid, _ = new_transfer(w)
    c = w.client(who)
    out = []
    for path in (f"/api/transfers/{tid}", f"/api/transfers/{tid}/ciphertext"):
        out.append(status(lambda p=path: c._req("GET", p))[0])
    return all(s == 404 for s in out), f"metadata→HTTP {out[0]}, ciphertext→HTTP {out[1]}"


@scenario("Authorization", "Other investigator requests Bob's evidence", "404 on metadata and ciphertext")
def _(w): return _denied(w, "carol")


@scenario("Authorization", "Sender requests the ciphertext back", "404: only the receiver can download")
def _(w): return _denied(w, "alice")


@scenario("Authorization", "Another officer requests Bob's evidence", "404")
def _(w): return _denied(w, "mallory")


@scenario("Authorization", "Administrator requests Bob's evidence", "404: admins manage users, not evidence")
def _(w): return _denied(w, "admin")


@scenario("Authorization", "Unknown and forbidden IDs are indistinguishable", "Same answer, so IDs cannot be probed")
def _(w):
    tid, _ = new_transfer(w)
    carol = w.client("carol")
    r1 = requests.get(f"{w.url}/api/transfers/{tid}", headers={"Authorization": f"Bearer {carol.token}"}, verify=False)
    r2 = requests.get(f"{w.url}/api/transfers/{os.urandom(16).hex()}", headers={"Authorization": f"Bearer {carol.token}"}, verify=False)
    return (r1.status_code, r1.json()) == (r2.status_code, r2.json()), f"existing→{r1.status_code} {r1.json()}, random→{r2.status_code} {r2.json()}"


@scenario("Authorization", "Investigator tries to upload evidence", "403: wrong role")
def _(w):
    st, msg = status(lambda: w.client("bob").send(w.priv["bob"], "carol", b"x", "x.txt"))
    return st in (403, 404), f"HTTP {st}: {msg}"


@scenario("Authorization", "Non-admins read the audit log", "403 for officer and investigator")
def _(w):
    s = [status(lambda u=u: w.client(u)._req("GET", "/api/audit"))[0] for u in ("alice", "bob")]
    return s == [403, 403], f"officer→HTTP {s[0]}, investigator→HTTP {s[1]}"


@scenario("Authorization", "Inbox shows only your own evidence", "Carol's inbox is empty")
def _(w):
    new_transfer(w, to="bob")
    n_bob, n_carol = len(w.client("bob").inbox()), len(w.client("carol").inbox())
    return n_bob >= 1 and n_carol == 0, f"bob sees {n_bob}, carol sees {n_carol}"


# ================================================================= AUTHENTICATION
@scenario("Authentication", "Request without a token", "401")
def _(w):
    st, _ = status(lambda: EvidenceClient(w.url)._req("GET", "/api/inbox"))
    return st == 401, f"HTTP {st}"


@scenario("Authentication", "Invented token", "401")
def _(w):
    c = EvidenceClient(w.url); c.token = "A" * 43
    st, _ = status(lambda: c.inbox())
    return st == 401, f"HTTP {st}"


@scenario("Authentication", "Expired token", "401")
def _(w):
    c = w.client("bob")
    w.db("UPDATE sessions SET expires_at=1 WHERE token_hash=%s", (hashlib.sha256(c.token.encode()).hexdigest(),))
    st, _ = status(lambda: c.inbox())
    return st == 401, f"HTTP {st}"


@scenario("Authentication", "Token used after logout", "401")
def _(w):
    c = w.client("bob")
    c._req("POST", "/api/logout")
    st, _ = status(lambda: c.inbox())
    return st == 401, f"HTTP {st}"


@scenario("Authentication", "Password guessing", "Account locks after 5 failures, even for the right password")
def _(w):
    c = EvidenceClient(w.url)
    fails = [status(lambda: c.login("carol", f"guess{i}"))[0] for i in range(5)]
    st, msg = status(lambda: c.login("carol", "carol-Passw0rd!"))
    w.db("UPDATE users SET failed_attempts=0, locked_until=0")
    return fails == [401] * 5 and st == 429, f"5 wrong guesses→{fails}; correct password afterwards→HTTP {st} ({msg})"


@scenario("Authentication", "Passwords and tokens are stored hashed", "No plaintext secrets in the database")
def _(w):
    c = w.client("bob")
    pw = w.db("SELECT password_hash FROM users WHERE username='bob'")[0]["password_hash"]
    tok = w.db("SELECT token_hash FROM sessions WHERE user_id=(SELECT id FROM users WHERE username='bob') ORDER BY created_at DESC LIMIT 1")[0]["token_hash"]
    ok = "bob-Passw0rd!" not in pw and c.token not in tok and len(tok) == 64 and ("$" in pw or ":" in pw)
    return ok, \
        f"password stored as '{pw[:22]}…', session token stored as SHA-256 '{tok[:16]}…'"


# ================================================================= REPLAY
@scenario("Replay", "Exact copy of an upload resent", "409: nonce already used")
def _(w):
    alice = w.client("alice")
    form, blob = alice.build_transfer(w.priv["alice"], "bob", b"once only", "once.txt")
    alice.post_transfer(form, blob)
    st, msg = status(lambda: alice.post_transfer(form, blob))
    return st == 409, f"HTTP {st}: {msg}"


@scenario("Replay", "Upload signed an hour ago", "400: outside the ±300 s window")
def _(w):
    alice = w.client("alice")
    form, blob = alice.build_transfer(w.priv["alice"], "bob", b"old", "old.txt", ts=int(time.time()) - 3600)
    st, msg = status(lambda: alice.post_transfer(form, blob))
    return st == 400, f"HTTP {st}: {msg}"


@scenario("Replay", "Upload signed an hour in the future", "400")
def _(w):
    alice = w.client("alice")
    form, blob = alice.build_transfer(w.priv["alice"], "bob", b"future", "future.txt", ts=int(time.time()) + 3600)
    st, msg = status(lambda: alice.post_transfer(form, blob))
    return st == 400, f"HTTP {st}: {msg}"


# ================================================================= INJECTION
@scenario("Injection", "SQL injection and path traversal in the transfer ID", "404; database untouched")
def _(w):
    before = w.db("SELECT COUNT(*) n FROM users")[0]["n"]
    c = w.client("bob")
    sts = [status(lambda i=i: c._req("GET", f"/api/transfers/{i}"))[0]
           for i in ("1' OR '1'='1", "../../etc/passwd", "0" * 32, "%00", "1; DROP TABLE users")]
    after = w.db("SELECT COUNT(*) n FROM users")[0]["n"]
    return all(s == 404 for s in sts) and before == after, f"statuses {sts}; users table {before}→{after} rows"


@scenario("Injection", "SQL injection in the login form", "401; no bypass")
def _(w):
    c = EvidenceClient(w.url)
    sts = [status(lambda u=u: c.login(u, "x' OR '1'='1"))[0] for u in ("alice' OR '1'='1' -- ", "' UNION SELECT 1,2,3 -- ")]
    return sts == [401, 401], f"statuses {sts}"


# ================================================================= ROBUSTNESS / NETWORK FAILURE
@scenario("Robustness", "Upload larger than the limit", "413")
def _(w):
    c = w.client("alice")
    r = requests.post(w.url + "/api/transfers", headers={"Authorization": f"Bearer {c.token}"},
                      files={"ciphertext": ("x", b"\0" * (3 * 1024 * 1024))}, data={"recipient": "bob"}, verify=False)
    return r.status_code == 413, f"HTTP {r.status_code} (limit set to 2 MB for this run)"


@scenario("Robustness", "Upload that is not an EVC1 envelope", "400")
def _(w):
    alice = w.client("alice")
    form, _ = alice.build_transfer(w.priv["alice"], "bob", b"data", "d.txt")
    st, msg = status(lambda: alice.post_transfer(form, b"this is plain text, not ciphertext " * 4))
    return st == 400, f"HTTP {st}: {msg}"


@scenario("Robustness", "Connection dropped mid-upload", "No half-stored transfer remains")
def _(w):
    c = w.client("alice")
    before = (w.db("SELECT COUNT(*) n FROM transfers")[0]["n"], len(os.listdir(w.storage_dir)))
    s = socket.create_connection(("127.0.0.1", w.port), timeout=5)
    boundary = "----cut"
    head = (f"POST /api/transfers HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {c.token}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: 900000\r\n\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"recipient\"\r\n\r\nbob\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"ciphertext\"; filename=\"e.bin\"\r\n\r\n").encode()
    if w.tls:
        import ssl
        s = ssl.create_default_context(cafile=w.tls[0]).wrap_socket(s, server_hostname="localhost")
    s.sendall(head + os.urandom(3000))
    s.close()                                    # vanish before the body is complete
    time.sleep(1.5)
    after = (w.db("SELECT COUNT(*) n FROM transfers")[0]["n"], len(os.listdir(w.storage_dir)))
    return before == after, f"transfers/files before {before}, after {after}"


@scenario("Robustness", "Server unreachable", "Client fails fast with a clear error")
def _(w):
    t0 = time.time()
    try:
        EvidenceClient("http://127.0.0.1:1", timeout=5).login("bob", "x")
        return False, "unexpectedly succeeded"
    except requests.exceptions.ConnectionError as e:
        return time.time() - t0 < 5, f"ConnectionError after {time.time() - t0:.2f}s (no hang, nothing stored)"


# ================================================================= AUDIT (last: they alter then restore audit rows)
def _chain(w):
    return w.client("admin")._req("GET", "/api/audit/verify").json()


@scenario("Audit", "Chain of custody verifies after all the activity above", "Chain intact")
def _(w):
    r = _chain(w)
    return r["ok"], f"{r['entries']} entries, intact={r['ok']}"


@scenario("Audit", "A log entry is edited in the database", "Chain breaks at that entry")
def _(w):
    row = w.db("SELECT id, actor FROM audit_log WHERE action='LOGIN_OK' ORDER BY id LIMIT 1")[0]
    w.db("UPDATE audit_log SET actor='someone-else' WHERE id=%s", (row["id"],))
    r = _chain(w)
    w.db("UPDATE audit_log SET actor=%s WHERE id=%s", (row["actor"], row["id"]))
    return (not r["ok"]) and r.get("first_bad_id") == row["id"], f"edited entry #{row['id']}; verifier reports ok={r['ok']}, first bad entry #{r.get('first_bad_id')}"


@scenario("Audit", "A log entry is deleted from the database", "Chain breaks")
def _(w):
    row = w.db("SELECT * FROM audit_log WHERE action='LOGIN_OK' ORDER BY id LIMIT 1 OFFSET 2")[0]
    w.db("DELETE FROM audit_log WHERE id=%s", (row["id"],))
    r = _chain(w)
    cols = list(row)
    w.db(f"INSERT INTO audit_log ({','.join(cols)}) VALUES ({','.join(['%s'] * len(cols))})", tuple(row[c] for c in cols))
    return not r["ok"], f"deleted entry #{row['id']}; verifier reports ok={r['ok']}"


@scenario("Audit", "Chain verifies again once the rows are restored", "Chain intact (proves the checks above were real)")
def _(w):
    r = _chain(w)
    return r["ok"], f"{r['entries']} entries, intact={r['ok']}"


# ================================================================= runner
def run(db=None, quiet=False, out_path=None):
    w = DemoWorld(db_name=db, max_upload_mb=2).start()
    results = []
    try:
        for i, (cat, title, expected, fn) in enumerate(SCENARIOS, 1):
            t0 = time.perf_counter()
            try:
                passed, observed = fn(w)
            except Exception as e:                                   # a crash is a failed scenario, never a silent pass
                passed, observed = False, f"scenario crashed: {type(e).__name__}: {e}"
            results.append(dict(id=i, category=cat, title=title, expected=expected, observed=str(observed),
                                passed=bool(passed), ms=round((time.perf_counter() - t0) * 1000, 1)))
            if not quiet:
                print(f"{'PASS' if passed else 'FAIL'}  [{cat}] {title}\n        {observed}")
    finally:
        w.stop()
    cats = {}
    for r in results:
        c = cats.setdefault(r["category"], dict(passed=0, total=0))
        c["total"] += 1
        c["passed"] += r["passed"]
    report = dict(generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  database=w.db_name, python=platform.python_version(),
                  scheme="AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC), RSA-2048 OAEP/PSS",
                  summary=dict(total=len(results), passed=sum(r["passed"] for r in results),
                               failed=sum(not r["passed"] for r in results), by_category=cats),
                  scenarios=results)
    out_path = out_path or os.path.join(ROOT, "report", "security_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(report, open(out_path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    return report, out_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", help="test database name (default: evidence_test)")
    a = ap.parse_args()
    rep, path = run(a.db)
    s = rep["summary"]
    print(f"\n{s['passed']}/{s['total']} scenarios passed  ->  {path}")
    sys.exit(0 if s["failed"] == 0 else 1)
