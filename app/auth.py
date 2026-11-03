import base64, binascii, hashlib, re, secrets, time
from functools import wraps
from flask import Blueprint, request, jsonify, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from .db import query, execute
from .limiter import limiter
from . import audit, keys

bp = Blueprint("auth", __name__)
DUMMY_HASH = generate_password_hash("dummy-password-for-timing")
MAX_FAILS, LOCK_SECONDS, SESSION_TTL = 5, 300, 8 * 3600
ROLES = ("officer", "investigator", "admin")


def err(msg, code):
    return jsonify(error=msg), code


def b64(s, field):
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise ValueError(f"{field} is not valid base64")


def require_auth(roles=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                return err("missing token", 401)
            th = hashlib.sha256(h[7:].encode()).hexdigest()
            row = query("SELECT u.id, u.username, u.role, s.expires_at FROM sessions s "
                        "JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s", (th,), one=True)
            if not row or row["expires_at"] < time.time():
                audit.log("-", "AUTH_INVALID_TOKEN", request.path, "invalid or expired token")
                return err("invalid or expired token", 401)
            g.user = row
            if roles and row["role"] not in roles:
                audit.log(row["username"], "AUTHZ_DENIED_ROLE", request.path,
                          f"role {row['role']} not permitted")
                return err("forbidden", 403)
            return fn(*a, **kw)
        return wrapper
    return deco


@bp.post("/api/login")
@limiter.limit(lambda: current_app.config["LOGIN_RATE"])
def login():
    d = request.get_json(silent=True) or {}
    u, p = str(d.get("username", ""))[:64], str(d.get("password", ""))
    row = query("SELECT * FROM users WHERE username = %s", (u,), one=True)
    now = int(time.time())
    if row and row["locked_until"] > now:
        audit.log(u, "LOGIN_LOCKED", "-", "attempt while locked")
        return err("account temporarily locked", 429)
    ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, p) and row is not None
    if not ok:
        if row:
            fails = row["failed_attempts"] + 1
            lock = now + LOCK_SECONDS if fails >= MAX_FAILS else 0
            execute("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
                    (0 if lock else fails, lock, row["id"]))
        audit.log(u, "LOGIN_FAILED", "-", "bad credentials")
        return err("invalid credentials", 401)
    execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=%s", (row["id"],))
    token = secrets.token_urlsafe(32)
    execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (%s,%s,%s,%s)",
            (hashlib.sha256(token.encode()).hexdigest(), row["id"], now, now + SESSION_TTL))
    audit.log(u, "LOGIN_OK", "-", row["role"])
    return jsonify(token=token, username=u, role=row["role"], expires_at=now + SESSION_TTL)


@bp.post("/api/logout")
@require_auth()
def logout():
    th = hashlib.sha256(request.headers["Authorization"][7:].encode()).hexdigest()
    execute("DELETE FROM sessions WHERE token_hash=%s", (th,))
    audit.log(g.user["username"], "LOGOUT")
    return jsonify(ok=True)


@bp.get("/api/me")
@require_auth()
def me():
    k = query("SELECT key_algo, fingerprint FROM user_keys WHERE user_id=%s AND revoked_at IS NULL",
              (g.user["id"],), one=True)
    return jsonify(username=g.user["username"], role=g.user["role"], active_key=k)


@bp.post("/api/admin/users")
@require_auth(roles=("admin",))
def create_user():
    d = request.get_json(silent=True) or {}
    u, p, role = str(d.get("username", "")), str(d.get("password", "")), d.get("role")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", u) or role not in ROLES or len(p) < 8:
        return err("invalid username/role or password shorter than 8", 400)
    if query("SELECT id FROM users WHERE username=%s", (u,), one=True):
        return err("username exists", 409)
    execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (%s,%s,%s,%s)",
            (u, generate_password_hash(p), role, int(time.time())))
    audit.log(g.user["username"], "USER_CREATED", u, role)
    return jsonify(ok=True), 201


@bp.put("/api/me/key")
@require_auth()
def register_key():
    """Bind a public key to the logged-in user. Requires proof of possession:
    a signature over (username, fingerprint) made with the matching private key."""
    d = request.get_json(silent=True) or {}
    try:
        pub, algo = keys.parse_public_key(str(d.get("public_key_pem", "")))
        sig = b64(d.get("pop_signature", ""), "pop_signature")
    except Exception as e:
        return err(f"bad key: {e}", 400)
    fp = keys.fingerprint(pub)
    if not keys.verify(pub, keys.pop_message(g.user["username"], fp), sig):
        audit.log(g.user["username"], "KEY_REGISTER_REJECTED", fp[:16], "proof of possession failed")
        return err("proof of possession failed", 400)
    if query("SELECT id FROM user_keys WHERE fingerprint=%s", (fp,), one=True):
        return err("key already registered", 409)
    now = int(time.time())
    execute("UPDATE user_keys SET revoked_at=%s WHERE user_id=%s AND revoked_at IS NULL", (now, g.user["id"]))
    execute("INSERT INTO user_keys (user_id,key_algo,public_key_pem,fingerprint,created_at) VALUES (%s,%s,%s,%s,%s)",
            (g.user["id"], algo, d["public_key_pem"], fp, now))
    audit.log(g.user["username"], "KEY_REGISTERED", fp[:16], algo)
    return jsonify(ok=True, fingerprint=fp, algo=algo), 201


@bp.get("/api/recipients")
@require_auth(roles=("officer", "admin"))
def recipients():
    """Directory of investigators who can receive evidence (with their active public keys)."""
    rows = query("SELECT u.username, k.key_algo, k.fingerprint, k.public_key_pem FROM users u "
                 "JOIN user_keys k ON k.user_id=u.id AND k.revoked_at IS NULL "
                 "WHERE u.role='investigator' ORDER BY u.username")
    return jsonify(recipients=rows)


@bp.get("/api/audit")
@require_auth(roles=("admin",))
def audit_list():
    limit = min(int(request.args.get("limit", 200)), 1000)
    return jsonify(entries=query("SELECT * FROM audit_log ORDER BY id DESC LIMIT %s", (limit,)))


@bp.get("/api/audit/verify")
@require_auth(roles=("admin",))
def audit_verify():
    return jsonify(audit.verify_chain())
