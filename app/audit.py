"""Hash-chained audit log: each entry commits to the previous entry's hash,
so editing/deleting any row breaks verification from that point on."""
import hashlib, threading, datetime
from flask import request, has_request_context
from .db import query, execute

_lock = threading.Lock()
GENESIS = "0" * 64


def _h(prev, ts, actor, action, target, detail, ip):
    s = "|".join([prev, ts, actor, action, target, detail, ip])
    return hashlib.sha256(s.encode()).hexdigest()


def log(actor, action, target="-", detail="-"):
    ip = (request.remote_addr or "-") if has_request_context() else "-"
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    detail = str(detail)[:500]
    with _lock:
        last = query("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE", one=True)
        prev = last["entry_hash"] if last else GENESIS
        eh = _h(prev, ts, actor, action, target, detail, ip)
        execute("INSERT INTO audit_log (ts,actor,action,target,detail,ip,prev_hash,entry_hash) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (ts, actor, action, target, detail, ip, prev, eh))


def verify_chain():
    prev = GENESIS
    rows = query("SELECT * FROM audit_log ORDER BY id ASC")
    for r in rows:
        exp = _h(prev, r["ts"], r["actor"], r["action"], r["target"], r["detail"], r["ip"])
        if r["prev_hash"] != prev or r["entry_hash"] != exp:
            return {"ok": False, "first_bad_id": r["id"], "entries": len(rows)}
        prev = r["entry_hash"]
    return {"ok": True, "entries": len(rows)}
