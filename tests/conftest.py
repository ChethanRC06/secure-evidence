import os, sys, threading, time
import pymysql, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from werkzeug.serving import make_server
from werkzeug.security import generate_password_hash
from app import create_app
from app.db import init_schema
from client.api import EvidenceClient
from client import envelope as E

USERS = [("admin", "admin"), ("alice", "officer"), ("mallory", "officer"),
         ("bob", "investigator"), ("carol", "investigator")]
TABLES = ["metrics", "transfers", "sessions", "user_keys", "audit_log", "users"]


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    app = create_app(dict(DB_NAME="evidence_test", STORAGE_DIR=str(tmp_path_factory.mktemp("storage")),
                          REPORT_DIR=str(tmp_path_factory.mktemp("reports")), LOGIN_RATE="1000 per minute"))
    init_schema(app.config)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield dict(url=f"http://127.0.0.1:{srv.server_port}", cfg=app.config)
    srv.shutdown()


@pytest.fixture(scope="session")
def privkeys():
    return {n: E.generate_rsa() for n, _ in USERS}


class World:
    def __init__(self, server, privkeys):
        self.url, self.cfg, self.priv = server["url"], server["cfg"], privkeys

    def db(self, sql, args=()):
        c = pymysql.connect(host=self.cfg["DB_HOST"], port=self.cfg["DB_PORT"], user=self.cfg["DB_USER"],
                            password=self.cfg["DB_PASSWORD"], database=self.cfg["DB_NAME"],
                            cursorclass=pymysql.cursors.DictCursor)
        with c.cursor() as cur:
            cur.execute(sql, args)
            rows = cur.fetchall()
        c.commit(); c.close()
        return rows

    def client(self, name, password=None):
        c = EvidenceClient(self.url)
        c.login(name, password or f"{name}-Passw0rd!")
        return c

    def audit_actions(self):
        return [r["action"] for r in self.db("SELECT action FROM audit_log ORDER BY id")]


@pytest.fixture()
def world(server, privkeys):
    cfg = server["cfg"]
    c = pymysql.connect(host=cfg["DB_HOST"], port=cfg["DB_PORT"], user=cfg["DB_USER"],
                        password=cfg["DB_PASSWORD"], database=cfg["DB_NAME"])
    with c.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for t in TABLES:
            cur.execute(f"TRUNCATE TABLE {t}")
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        for n, role in USERS:
            cur.execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (%s,%s,%s,%s)",
                        (n, generate_password_hash(f"{n}-Passw0rd!", method="pbkdf2:sha256:1000"), role, int(time.time())))
    c.commit(); c.close()
    w = World(server, privkeys)
    for n in ("alice", "mallory", "bob", "carol"):       # each user registers THEIR OWN key
        w.client(n).register_key(privkeys[n])
    return w
