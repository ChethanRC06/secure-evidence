"""Command-line client.  Examples:
  python -m client.cli keygen alice
  python -m client.cli --server http://localhost:5000 --user alice register-key --key keys/alice.pem
  python -m client.cli --user alice send --key keys/alice.pem --to bob evidence.jpg
  python -m client.cli --user bob inbox
  python -m client.cli --user bob receive --key keys/bob.pem <transfer-id> --out downloads/
Password: --password or EV_PASSWORD env var (default <user>-Passw0rd! for demo users)."""
import argparse, os, sys
from . import envelope as E
from .api import EvidenceClient, ApiError


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default=os.environ.get("EV_SERVER", "http://localhost:5000"))
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--cacert", help="CA/self-signed cert file for HTTPS, or 'insecure'")
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen"); kg.add_argument("name"); kg.add_argument("--dir", default="keys")
    rk = sub.add_parser("register-key"); rk.add_argument("--key", required=True)
    sub.add_parser("recipients")
    sn = sub.add_parser("send"); sn.add_argument("--key", required=True); sn.add_argument("--to", required=True); sn.add_argument("file")
    sub.add_parser("inbox"); sub.add_parser("sent")
    rc = sub.add_parser("receive"); rc.add_argument("--key", required=True); rc.add_argument("id"); rc.add_argument("--out", default=".")
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        os.makedirs(a.dir, exist_ok=True)
        priv = E.generate_rsa()
        p = os.path.join(a.dir, a.name + ".pem")
        with open(p, "wb") as f:
            os.chmod(p, 0o600); f.write(E.priv_pem(priv))
        open(os.path.join(a.dir, a.name + ".pub.pem"), "w").write(E.pub_pem(priv))
        print(f"private key: {p}  (keep secret)\nfingerprint: {E.fingerprint(priv.public_key())}")
        return 0

    verify = False if a.cacert == "insecure" else (a.cacert or True)
    c = EvidenceClient(a.server, verify=verify)
    pw = a.password or os.environ.get("EV_PASSWORD") or f"{a.user}-Passw0rd!"
    try:
        c.login(a.user, pw)
        if a.cmd == "register-key":
            print(c.register_key(E.load_private(a.key)))
        elif a.cmd == "recipients":
            for r in c.recipients(): print(r["username"], r["key_algo"], r["fingerprint"])
        elif a.cmd == "send":
            res = c.send(E.load_private(a.key), a.to, open(a.file, "rb").read(), os.path.basename(a.file))
            print(res)
            t = c.last_timings
            print("timing (ms): encrypt={encrypt_ms:.2f}  key-wrap={wrap_ms:.2f}  hash={hash_ms:.2f}  "
                  "sign={sign_ms:.2f}  total-crypto={total_ms:.2f}  upload={transfer_ms:.2f}".format(**t))
            try: c.report_metrics(res["id"], "send")
            except ApiError: pass
        elif a.cmd in ("inbox", "sent"):
            for t in (c.inbox() if a.cmd == "inbox" else c.sent()):
                print(t["id"], t.get("sender") or t.get("recipient"), t["category"], t["size_bytes"], t["filename"])
        elif a.cmd == "receive":
            plain, rep = c.receive(a.id, E.load_private(a.key))
            os.makedirs(a.out, exist_ok=True)
            dest = os.path.join(a.out, os.path.basename(rep["filename"]))
            open(dest, "wb").write(plain)
            print(f"saved {dest}\nfrom {rep['sender']} (key {rep['sender_key_fp'][:16]}…)  "
                  f"signature={rep['signature_valid']} mac={rep['mac_valid']}\nsha256={rep['plaintext_sha256']}")
            t = rep["timings"]
            print("timing (ms): signature-verify={verify_ms:.2f}  key-unwrap={unwrap_ms:.2f}  "
                  "decrypt={decrypt_ms:.2f}  total-crypto={total_ms:.2f}  download={transfer_ms:.2f}".format(**t))
            try: c.report_metrics(a.id, "receive", t)
            except ApiError: pass
    except (ApiError, E.IntegrityError) as e:
        print("ERROR:", e, file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
