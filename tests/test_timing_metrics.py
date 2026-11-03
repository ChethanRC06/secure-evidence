"""Timing instrumentation: sender encryption time, receiver decryption time, signature generation and
verification time, the metrics API (who may report/read what), the report endpoint, and the browser
tamper test (run under Node with the same crypto.js the browser uses)."""
import json, os, subprocess
import pytest
from client.api import EvidenceClient, ApiError

HERE = os.path.dirname(__file__)
KEYS_SEND = {"encrypt_ms", "wrap_ms", "hash_ms", "sign_ms", "total_ms", "transfer_ms", "plaintext_bytes", "ciphertext_bytes"}
KEYS_RECV = {"hash_ms", "verify_ms", "unwrap_ms", "decrypt_ms", "total_ms", "transfer_ms", "plaintext_bytes", "ciphertext_bytes"}


def send(w, who="alice", to="bob", data=b"timing test " * 500, name="t.txt"):
    c = w.client(who)
    res = c.send(w.priv[who], to, data, name)
    return c, res


# ---------------- Python client timings ----------------
def test_sender_timings_are_recorded(world):
    c, res = send(world)
    assert KEYS_SEND <= set(c.last_timings)
    assert all(c.last_timings[k] > 0 for k in ("encrypt_ms", "wrap_ms", "sign_ms", "total_ms", "transfer_ms"))
    assert c.last_timings["ciphertext_bytes"] > c.last_timings["plaintext_bytes"]      # IV + padding + MAC tag overhead


def test_receiver_timings_are_recorded(world):
    _, res = send(world)
    bob = world.client("bob")
    plain, rep = bob.receive(res["id"], world.priv["bob"])
    assert KEYS_RECV <= set(rep["timings"]) and rep["timings"]["decrypt_ms"] > 0 and rep["timings"]["verify_ms"] > 0


def test_server_records_its_own_signature_verification_time(world):
    _, res = send(world)
    assert res["server_ms"]["verify_ms"] > 0 and res["ciphertext_bytes"] > 0
    row = world.db("SELECT kind, verify_ms, hash_ms FROM metrics WHERE transfer_id=%s", (res["id"],))[0]
    assert row["kind"] == "server" and row["verify_ms"] > 0 and row["hash_ms"] >= 0


# ---------------- metrics API authorization and validation ----------------
def test_each_side_can_report_only_its_own_role(world):
    alice, res = send(world); tid = res["id"]
    bob, carol = world.client("bob"), world.client("carol")
    alice.report_metrics(tid, "send")                                       # sender reports 'send'
    bob.report_metrics(tid, "receive", {"decrypt_ms": 1.5, "verify_ms": 0.7, "plaintext_bytes": 10})
    for who, kind in ((bob, "send"), (alice, "receive"), (carol, "receive"), (carol, "send")):
        with pytest.raises(ApiError) as e:
            who.report_metrics(tid, kind, {"total_ms": 1})
        assert e.value.status == 404
    assert "AUTHZ_DENIED_METRICS" in world.audit_actions()


@pytest.mark.parametrize("bad", [{"encrypt_ms": -1}, {"encrypt_ms": "fast"}, {"encrypt_ms": 10 ** 9}, {"sign_ms": True},
                                 {"plaintext_bytes": -5}, {"kind": "other"}, {"transfer_id": "../../etc/passwd"}])
def test_invalid_metrics_are_rejected(world, bad):
    alice, res = send(world)
    body = dict(transfer_id=res["id"], kind="send", total_ms=1.0); body.update(bad)
    with pytest.raises(ApiError) as e:
        alice._req("POST", "/api/metrics", json=body)
    assert e.value.status == 400


def test_metrics_visibility(world):
    alice, res = send(world); tid = res["id"]
    alice.report_metrics(tid, "send")
    bob = world.client("bob"); bob.receive(tid, world.priv["bob"]); bob.report_metrics(tid, "receive")
    a = alice._req("GET", "/api/metrics").json()["metrics"]
    b = bob._req("GET", "/api/metrics").json()["metrics"]
    c = world.client("carol")._req("GET", "/api/metrics").json()["metrics"]
    adm = world.client("admin")._req("GET", "/api/metrics").json()["metrics"]
    assert {m["kind"] for m in a} == {"send", "server"} and all(m["username"] == "alice" for m in a)
    assert {m["kind"] for m in b} == {"receive"} and all(m["username"] == "bob" for m in b)
    assert c == []
    assert {m["username"] for m in adm} == {"alice", "bob"} and len(adm) == 3
    assert all(m["filename"] == "t.txt" for m in adm)


def test_metrics_require_authentication_and_cap(world):
    with pytest.raises(ApiError) as e:
        EvidenceClient(world.url)._req("GET", "/api/metrics")
    assert e.value.status == 401
    alice, res = send(world)
    for _ in range(50):
        alice.report_metrics(res["id"], "send", {"total_ms": 1})
    with pytest.raises(ApiError) as e:
        alice.report_metrics(res["id"], "send", {"total_ms": 1})
    assert e.value.status == 429


# ---------------- generated reports ----------------
def test_reports_endpoint(world):
    c = world.client("bob")
    assert c._req("GET", "/api/reports/security").json() == {"available": False}
    path = os.path.join(world.cfg["REPORT_DIR"], "security_results.json")
    open(path, "w").write(json.dumps({"summary": {"passed": 3, "total": 3}}))
    r = c._req("GET", "/api/reports/security").json()
    assert r["available"] and r["report"]["summary"]["passed"] == 3
    open(path, "w").write("{not json")
    assert c._req("GET", "/api/reports/security").json()["available"] is False
    for bad in ("secrets", "..", "security_results.json"):
        with pytest.raises(ApiError) as e:
            c._req("GET", f"/api/reports/{bad}")
        assert e.value.status == 404
    with pytest.raises(ApiError) as e:
        EvidenceClient(world.url)._req("GET", "/api/reports/security")
    assert e.value.status == 401


# ---------------- browser crypto: timings + tamper test (same crypto.js as the browser) ----------------
def test_browser_tamper_test_detects_every_attack():
    r = subprocess.run(["node", os.path.join(HERE, "js_selftest.js")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    missed = [a["name"] for a in d["attacks"] if not a["detected"]]
    assert len(d["attacks"]) == 10 and not missed, missed
    # each attack must fail for the *intended* reason, not by accident
    reasons = {a["name"]: a["message"] for a in d["attacks"]}
    assert "hash" in reasons["Flip one bit inside the ciphertext"]
    assert "MAC" in reasons["Flip one bit, skipping the hash check"]
    assert "MAC" in reasons["Change the IV"] and "MAC" in reasons["Change the MAC tag"]
    assert "unwrap" in reasons["Corrupt the wrapped key"] and "unwrap" in reasons["Decrypt with a different private key"]
    assert "signature" in reasons["Change the signed file name"] and "signature" in reasons["Corrupt the signature"]
    s, rcv = d["sendTimings"], d["receiveTimings"]
    assert all(s[k] > 0 for k in ("encrypt_ms", "wrap_ms", "sign_ms", "total_ms"))
    assert all(rcv[k] > 0 for k in ("verify_ms", "unwrap_ms", "decrypt_ms", "total_ms"))
