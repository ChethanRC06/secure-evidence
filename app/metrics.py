"""Performance metrics (encryption, decryption, signature times) and generated analysis reports.

* Clients measure their own crypto times and post them here; the server also records its own
  signature-verification time at upload (kind='server', see transfers.upload).
* Client-reported numbers are informational only: they are never used for any security decision.
* /api/reports/<name> serves the JSON files written by scripts/benchmark.py, scripts/security_analysis.py
  and scripts/capture_packets.py so the web UI can display them.
"""
import json, os, re, time
from flask import Blueprint, request, jsonify, g, current_app, send_from_directory
from .db import query, execute
from .auth import require_auth, err
from . import audit

bp = Blueprint("metrics", __name__)
TID = re.compile(r"[0-9a-f]{32}")
MS_FIELDS = ("encrypt_ms", "decrypt_ms", "aes_ms", "mac_ms", "hash_ms", "wrap_ms", "unwrap_ms",
             "sign_ms", "verify_ms", "total_ms", "transfer_ms")
MAX_MS = 3_600_000.0                      # one hour: anything above is certainly bogus
MAX_PER_TRANSFER = 50                     # per user, per transfer, per kind
REPORTS = {"security": "security_results.json", "capture": "capture_results.json",
           "benchmark": "benchmark_results.json"}


def _num(v, hi):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v < 0 or v > hi:
        raise ValueError("bad number")
    return float(v)


@bp.post("/api/metrics")
@require_auth()
def post_metrics():
    d = request.get_json(silent=True) or {}
    tid, kind = str(d.get("transfer_id", "")), d.get("kind")
    if kind not in ("send", "receive") or not TID.fullmatch(tid):
        return err("invalid metrics", 400)
    try:
        vals = {f: _num(d.get(f), MAX_MS) for f in MS_FIELDS}
        pt, ct = int(_num(d.get("plaintext_bytes", 0), 2 ** 40)), int(_num(d.get("ciphertext_bytes", 0), 2 ** 40))
    except (ValueError, TypeError):
        return err("invalid metrics", 400)
    col = "sender_id" if kind == "send" else "recipient_id"      # you can only report on your own side
    if not query(f"SELECT id FROM transfers WHERE id=%s AND {col}=%s", (tid, g.user["id"]), one=True):
        audit.log(g.user["username"], "AUTHZ_DENIED_METRICS", tid[:40], f"kind={kind}")
        return err("not found", 404)
    n = query("SELECT COUNT(*) AS n FROM metrics WHERE transfer_id=%s AND user_id=%s AND kind=%s",
              (tid, g.user["id"], kind), one=True)["n"]
    if n >= MAX_PER_TRANSFER:
        return err("too many measurements for this transfer", 429)
    cols = ["transfer_id", "user_id", "kind", "plaintext_bytes", "ciphertext_bytes", *MS_FIELDS, "created_at"]
    execute(f"INSERT INTO metrics ({','.join(cols)}) VALUES ({','.join(['%s'] * len(cols))})",
            (tid, g.user["id"], kind, pt, ct, *[vals[f] for f in MS_FIELDS], int(time.time())))
    return jsonify(ok=True), 201


@bp.get("/api/metrics")
@require_auth()
def list_metrics():
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except ValueError:
        return err("bad limit", 400)
    base = ("SELECT m.id, m.transfer_id, m.kind, m.plaintext_bytes, m.ciphertext_bytes, " +
            ", ".join("m." + f for f in MS_FIELDS) + ", m.created_at, t.filename, u.username "
            "FROM metrics m JOIN transfers t ON t.id=m.transfer_id JOIN users u ON u.id=m.user_id ")
    if g.user["role"] == "admin":
        rows = query(base + "ORDER BY m.id DESC LIMIT %s", (limit,))
    else:                                           # senders also get their own 'server' rows (user_id = sender)
        rows = query(base + "WHERE m.user_id=%s ORDER BY m.id DESC LIMIT %s", (g.user["id"], limit))
    return jsonify(metrics=rows)


@bp.get("/api/reports/<name>")
@require_auth()
def get_report(name):
    fn = REPORTS.get(name)
    if not fn:
        return err("not found", 404)
    path = os.path.join(current_app.config["REPORT_DIR"], fn)
    if not os.path.isfile(path):
        return jsonify(available=False)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return jsonify(available=False, error="report file could not be read")
    return jsonify(available=True, report=data, modified=int(os.path.getmtime(path)))


CAPTURE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,80}\.pcapng?")


@bp.get("/api/captures/<name>")
@require_auth()
def get_capture(name):
    """Packet-capture files written by scripts/capture_packets.py. Only plain *.pcap / *.pcapng names are served."""
    folder = os.path.join(current_app.config["REPORT_DIR"], "captures")
    if not CAPTURE_NAME.fullmatch(name) or not os.path.isfile(os.path.join(folder, name)):
        return err("not found", 404)
    return send_from_directory(folder, name, as_attachment=True, mimetype="application/octet-stream")
