import base64, hashlib, os, re, time, uuid
import pymysql
from flask import Blueprint, request, jsonify, g, current_app, Response
from .db import query, execute, get_db
from .auth import require_auth, err, b64
from . import audit, keys

bp = Blueprint("transfers", __name__)
TID = re.compile(r"[0-9a-f]{32}")
MAGIC = b"EVC1"
MIN_CT = 4 + 16 + 16 + 32            # magic + iv + >=1 AES block + HMAC tag
SKEW = 300                            # seconds of allowed clock skew / replay window
EXT = {"text": {"txt", "md", "csv", "log"}, "image": {"png", "jpg", "jpeg", "gif", "bmp", "webp"},
       "audio": {"mp3", "wav", "ogg", "m4a", "flac"}, "video": {"mp4", "webm", "mkv", "avi", "mov"},
       "document": {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt"}}


def categorize(filename, mime):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    for cat, exts in EXT.items():
        if ext in exts:
            return cat
    head = (mime or "").split("/")[0]
    return head if head in ("text", "image", "audio", "video") else "other"


def _row_public(t):
    return {"id": t["id"], "sender": t.get("sender"), "recipient": t.get("recipient"),
            "filename": t["filename"], "mime_type": t["mime_type"], "category": t["category"],
            "size_bytes": t["size_bytes"], "created_at": t["created_at"], "downloaded_at": t["downloaded_at"]}


@bp.post("/api/transfers")
@require_auth(roles=("officer",))
def upload():
    me = g.user["username"]
    f, form = request.files.get("ciphertext"), request.form
    need = ("recipient", "recipient_key_fp", "filename", "mime_type", "size", "timestamp",
            "nonce", "wrapped_key", "signature")
    if not f or any(not form.get(k) for k in need):
        return err("missing fields", 400)
    try:
        size, ts = int(form["size"]), int(form["timestamp"])
        wk, sig = b64(form["wrapped_key"], "wrapped_key"), b64(form["signature"], "signature")
    except ValueError as e:
        return err(str(e), 400)
    filename, mime, nonce = form["filename"], form["mime_type"], form["nonce"]
    if (len(filename) > 255 or any(ord(c) < 32 for c in filename + mime) or len(mime) > 100
            or not re.fullmatch(r"[0-9a-f]{32}", nonce) or size < 0 or not (64 <= len(wk) <= 1024)):
        return err("invalid metadata", 400)
    if abs(time.time() - ts) > SKEW:
        audit.log(me, "UPLOAD_REJECTED_STALE", filename, f"timestamp skew {int(time.time()-ts)}s")
        return err("timestamp outside allowed window", 400)

    data = f.read()
    if not (data[:4] == MAGIC and len(data) >= MIN_CT and (len(data) - 4 - 16 - 32) % 16 == 0):
        return err("ciphertext is not a valid EVC1 envelope", 400)

    rcpt = query("SELECT u.id, u.username, k.id AS key_id, k.fingerprint FROM users u "
                 "JOIN user_keys k ON k.user_id=u.id AND k.revoked_at IS NULL "
                 "WHERE u.username=%s AND u.role='investigator'", (form["recipient"],), one=True)
    if not rcpt:
        return err("unknown recipient or recipient has no registered key", 404)
    if rcpt["fingerprint"] != form["recipient_key_fp"]:
        audit.log(me, "UPLOAD_REJECTED_STALE_KEY", rcpt["username"], "recipient key fingerprint mismatch")
        return err("recipient key changed; refresh the directory", 409)
    sk = query("SELECT id, public_key_pem FROM user_keys WHERE user_id=%s AND revoked_at IS NULL",
               (g.user["id"],), one=True)
    if not sk:
        return err("register your public key first", 400)

    t0 = time.perf_counter()
    ct_sha = hashlib.sha256(data).hexdigest()
    hash_ms = (time.perf_counter() - t0) * 1000
    msg = keys.transfer_message(me, rcpt["username"], rcpt["fingerprint"], filename, mime, size,
                                ct_sha, hashlib.sha256(wk).hexdigest(), ts, nonce)
    pub, _ = keys.parse_public_key(sk["public_key_pem"])
    t0 = time.perf_counter()
    sig_ok = keys.verify(pub, msg, sig)
    verify_ms = (time.perf_counter() - t0) * 1000          # server-side signature verification time
    if not sig_ok:
        audit.log(me, "UPLOAD_REJECTED_BAD_SIGNATURE", filename, "signature invalid")
        return err("signature verification failed", 400)

    tid, now = uuid.uuid4().hex, int(time.time())
    try:
        execute("INSERT INTO transfers (id,sender_id,recipient_id,sender_key_id,recipient_key_id,filename,"
                "mime_type,category,size_bytes,ciphertext_path,ciphertext_sha256,wrapped_key,signature,"
                "signed_at,nonce,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (tid, g.user["id"], rcpt["id"], sk["id"], rcpt["key_id"], filename, mime,
                 categorize(filename, mime), size, tid + ".bin", ct_sha, wk, sig, ts, nonce, now))
    except pymysql.err.IntegrityError:
        audit.log(me, "REPLAY_REJECTED", filename, "duplicate nonce")
        return err("replay detected (nonce already used)", 409)
    with open(os.path.join(current_app.config["STORAGE_DIR"], tid + ".bin"), "wb") as out:
        out.write(data)
    execute("INSERT INTO metrics (transfer_id,user_id,kind,plaintext_bytes,ciphertext_bytes,hash_ms,verify_ms,created_at) "
            "VALUES (%s,%s,'server',%s,%s,%s,%s,%s)", (tid, g.user["id"], size, len(data), hash_ms, verify_ms, now))
    audit.log(me, "UPLOAD", tid, f"to={rcpt['username']} file={filename} ct_sha256={ct_sha[:16]}")
    return jsonify(id=tid, ciphertext_sha256=ct_sha, ciphertext_bytes=len(data),
                   server_ms={"hash_ms": round(hash_ms, 3), "verify_ms": round(verify_ms, 3)}), 201


@bp.get("/api/inbox")
@require_auth()
def inbox():
    rows = query("SELECT t.*, s.username AS sender FROM transfers t JOIN users s ON s.id=t.sender_id "
                 "WHERE t.recipient_id=%s ORDER BY t.created_at DESC, t.seq DESC", (g.user["id"],))
    return jsonify(transfers=[_row_public(r) for r in rows])


@bp.get("/api/sent")
@require_auth()
def sent():
    rows = query("SELECT t.*, r.username AS recipient FROM transfers t JOIN users r ON r.id=t.recipient_id "
                 "WHERE t.sender_id=%s ORDER BY t.created_at DESC, t.seq DESC", (g.user["id"],))
    return jsonify(transfers=[_row_public(r) for r in rows])


def _recipient_transfer(tid):
    """Single choke point for receiver authorization. Returns the row only if the
    caller is the intended recipient; otherwise audits and returns None (callers answer 404)."""
    t = TID.fullmatch(tid) and query(
        "SELECT t.*, s.username AS sender, r.username AS recipient, sk.public_key_pem AS sender_pem, "
        "sk.fingerprint AS sender_fp, rk.fingerprint AS recipient_fp FROM transfers t "
        "JOIN users s ON s.id=t.sender_id JOIN users r ON r.id=t.recipient_id "
        "JOIN user_keys sk ON sk.id=t.sender_key_id JOIN user_keys rk ON rk.id=t.recipient_key_id "
        "WHERE t.id=%s", (tid,), one=True)
    if not t or t["recipient_id"] != g.user["id"]:
        audit.log(g.user["username"], "AUTHZ_DENIED_TRANSFER", tid[:40],
                  "not the intended recipient" if t else "no such transfer")
        return None
    return t


@bp.get("/api/transfers/<tid>")
@require_auth()
def transfer_meta(tid):
    t = _recipient_transfer(tid)
    if not t:
        return err("not found", 404)
    d = _row_public(t)
    d.update(signed_at=t["signed_at"], nonce=t["nonce"], signature=base64.b64encode(t["signature"]).decode(),
             wrapped_key=base64.b64encode(t["wrapped_key"]).decode(), recipient_key_fp=t["recipient_fp"],
             sender_key_fp=t["sender_fp"], sender_public_key_pem=t["sender_pem"],
             ciphertext_sha256=t["ciphertext_sha256"])
    return jsonify(d)


@bp.get("/api/transfers/<tid>/ciphertext")
@require_auth()
def transfer_ciphertext(tid):
    t = _recipient_transfer(tid)
    if not t:
        return err("not found", 404)
    with open(os.path.join(current_app.config["STORAGE_DIR"], t["ciphertext_path"]), "rb") as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != t["ciphertext_sha256"]:
        audit.log(g.user["username"], "STORAGE_TAMPER_DETECTED", tid, "stored ciphertext hash mismatch")
        get_db().commit()          # keep the audit row: the after_request hook rolls back on 5xx responses
        return err("stored evidence failed integrity check", 500)
    execute("UPDATE transfers SET downloaded_at=COALESCE(downloaded_at, %s) WHERE id=%s", (int(time.time()), tid))
    audit.log(g.user["username"], "DOWNLOAD", tid, f"from={t['sender']} file={t['filename']}")
    return Response(data, mimetype="application/octet-stream",
                    headers={"X-Ciphertext-SHA256": t["ciphertext_sha256"]})
