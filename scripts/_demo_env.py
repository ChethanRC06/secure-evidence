"""Shared helper for the analysis scripts (security_analysis.py, capture_packets.py).

Starts the REAL application in-process on 127.0.0.1 against a TEST database, seeds the five demo users with
freshly generated RSA keys, and hands back ready-to-use clients. It never touches your live `evidence_db`:
the database name must contain "test" or "demo" because the tables are TRUNCATED on start.
"""
import datetime, ipaddress, logging, os, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pymysql
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server

from app import create_app, default_config
from app.bootstrap import ensure_database, explain
from app.db import init_schema
from client import envelope as E
from client.api import EvidenceClient

USERS = [("admin", "admin"), ("alice", "officer"), ("mallory", "officer"),
         ("bob", "investigator"), ("carol", "investigator")]
TABLES = ["metrics", "transfers", "sessions", "user_keys", "audit_log", "users"]


def make_self_signed(dirpath):
    """Write cert.pem / key.pem (self-signed, valid for localhost and 127.0.0.1). Returns (cert, key) paths."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evidence-demo")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    os.makedirs(dirpath, exist_ok=True)
    c, k = os.path.join(dirpath, "cert.pem"), os.path.join(dirpath, "key.pem")
    open(c, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(k, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return c, k


logging.getLogger("werkzeug").setLevel(logging.ERROR)          # keep script output readable


class DemoWorld:
    def __init__(self, db_name=None, port=0, tls=None, storage_dir=None, max_upload_mb=100, passwords=None):
        self.db_name = db_name or os.environ.get("EV_ANALYSIS_DB", "evidence_test")
        if not any(w in self.db_name.lower() for w in ("test", "demo")):
            raise SystemExit(f"Refusing to use database '{self.db_name}': its tables are emptied on every run, "
                             f"so the name must contain 'test' or 'demo'.")
        self.tls, self.port = tls, port
        self.passwords = dict(passwords or {})          # per-user overrides; default is '<name>-Passw0rd!'
        self.storage_dir = storage_dir or os.path.join(ROOT, "storage", "_analysis")
        self.cfg_over = dict(DB_NAME=self.db_name, STORAGE_DIR=self.storage_dir, LOGIN_RATE="100000 per minute",
                             MAX_CONTENT_LENGTH=max_upload_mb * 1024 * 1024)
        self.priv = {n: E.generate_rsa() for n, _ in USERS}
        self.srv = self.app = self.cfg = None

    # ---- lifecycle ----
    def start(self):
        cfg = dict(default_config(), **self.cfg_over)
        try:
            ensure_database(cfg)
            init_schema(cfg)
        except pymysql.err.Error as e:
            raise SystemExit(f"Cannot use test database '{self.db_name}': {explain(e, cfg)}\n"
                             f"Create it once as MySQL root:  CREATE DATABASE {self.db_name} CHARACTER SET utf8mb4;  "
                             f"GRANT ALL ON {self.db_name}.* TO '{cfg['DB_USER']}'@'localhost';")
        self.app = create_app(self.cfg_over)
        self.cfg = self.app.config
        os.makedirs(self.storage_dir, exist_ok=True)
        for f in os.listdir(self.storage_dir):
            if f.endswith(".bin"):
                os.remove(os.path.join(self.storage_dir, f))
        self.reset_db()
        ctx = (self.tls[0], self.tls[1]) if self.tls else None
        self.srv = make_server("127.0.0.1", self.port, self.app, threaded=True, ssl_context=ctx)
        self.port = self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}"
        for n, _ in USERS:
            if n not in ("admin",):
                self.client(n).register_key(self.priv[n])
        return self

    def stop(self):
        if self.srv:
            self.srv.shutdown()
            self.srv = None

    def reset_db(self):
        c = self._raw()
        with c.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            for t in TABLES:
                cur.execute(f"TRUNCATE TABLE {t}")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
            for n, role in USERS:
                cur.execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (%s,%s,%s,%s)",
                            (n, generate_password_hash(self.pw(n), method="pbkdf2:sha256:1000"), role, int(time.time())))
        c.commit(); c.close()

    # ---- helpers ----
    def pw(self, name):
        return self.passwords.get(name, f"{name}-Passw0rd!")

    def _raw(self):
        c = self.cfg
        return pymysql.connect(host=c["DB_HOST"], port=c["DB_PORT"], user=c["DB_USER"], password=c["DB_PASSWORD"],
                               database=c["DB_NAME"], cursorclass=pymysql.cursors.DictCursor)

    def db(self, sql, args=()):
        c = self._raw()
        with c.cursor() as cur:
            cur.execute(sql, args)
            rows = cur.fetchall()
        c.commit(); c.close()
        return rows

    def client(self, name, password=None):
        cl = EvidenceClient(self.url, verify=(self.tls[0] if self.tls else True))
        cl.login(name, password or self.pw(name))
        return cl
