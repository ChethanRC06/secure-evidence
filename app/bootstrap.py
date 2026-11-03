"""First-run setup shared by run.py and scripts/setup_db.py:
create the database (if the DB user may), create tables, seed demo users when the users table is empty."""
import os, time
import pymysql
from werkzeug.security import generate_password_hash

DEMO = [("admin", "admin"), ("alice", "officer"), ("mallory", "officer"),
        ("bob", "investigator"), ("carol", "investigator")]


def _connect(cfg, database=True):
    return pymysql.connect(host=cfg["DB_HOST"], port=cfg["DB_PORT"], user=cfg["DB_USER"],
                           password=cfg["DB_PASSWORD"], database=cfg["DB_NAME"] if database else None,
                           charset="utf8mb4", connect_timeout=5)


def explain(e, cfg):
    """Turn a pymysql error into a message a human can act on."""
    code = e.args[0] if e.args else 0
    f = dict(u=cfg["DB_USER"], h=cfg["DB_HOST"], p=cfg["DB_PORT"], d=cfg["DB_NAME"],
             c=code, m=e.args[1] if len(e.args) > 1 else e)
    table = {
        1045: "MySQL rejected the login for user '{u}'. Check DB_USER / DB_PASSWORD (defaults: evidence / evidence_pw).",
        2003: "Cannot reach MySQL at {h}:{p}. Is the MySQL service running? Check DB_HOST / DB_PORT.",
        2002: "Cannot reach MySQL. Is the MySQL service running?",
        1049: "Database '{d}' does not exist and could not be created. As MySQL root run: CREATE DATABASE {d} CHARACTER SET utf8mb4; GRANT ALL ON {d}.* TO '{u}'@'localhost'; FLUSH PRIVILEGES;",
        1044: "User '{u}' has no permission on database '{d}'. As MySQL root run: GRANT ALL ON {d}.* TO '{u}'@'localhost'; FLUSH PRIVILEGES;",
        1146: "Database tables are missing. Restart the app (it creates them) or run: python scripts/setup_db.py",
    }
    return table.get(code, "Database error {c}: {m}").format(**f)


def ensure_database(cfg):
    try:
        _connect(cfg).close()
        return
    except pymysql.err.OperationalError as e:
        if e.args[0] != 1049:
            raise
    c = _connect(cfg, database=False)          # database missing: try to create it
    with c.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg['DB_NAME']}` CHARACTER SET utf8mb4")
    c.close()


def seed_demo_users(cfg):
    conn = _connect(cfg)
    created = []
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            for name, role in DEMO:
                pw = os.environ.get(f"{name.upper()}_PASSWORD", f"{name}-Passw0rd!")
                cur.execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (%s,%s,%s,%s)",
                            (name, generate_password_hash(pw), role, int(time.time())))
                created.append(name)
    conn.commit(); conn.close()
    return created


def bootstrap(cfg, seed=True):
    """Returns (ok, message). Never raises for expected DB problems."""
    from .db import init_schema
    try:
        ensure_database(cfg)
        init_schema(cfg)
        made = seed_demo_users(cfg) if seed else []
        return True, ("Created demo users: " + ", ".join(made)) if made else "Database ready."
    except pymysql.err.Error as e:
        return False, explain(e, cfg)
