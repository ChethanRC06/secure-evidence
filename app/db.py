import os
import pymysql, pymysql.cursors
from flask import g, current_app


def get_db():
    if "db" not in g:
        c = current_app.config
        g.db = pymysql.connect(
            host=c["DB_HOST"], port=c["DB_PORT"], user=c["DB_USER"],
            password=c["DB_PASSWORD"], database=c["DB_NAME"], charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor, autocommit=False)
    return g.db


def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def query(sql, args=(), one=False):
    with get_db().cursor() as cur:
        cur.execute(sql, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    with get_db().cursor() as cur:
        cur.execute(sql, args)
        return cur.lastrowid


def init_schema(config):
    """Create tables (idempotent). Used by setup script and tests."""
    conn = pymysql.connect(host=config["DB_HOST"], port=config["DB_PORT"],
                           user=config["DB_USER"], password=config["DB_PASSWORD"],
                           database=config["DB_NAME"], charset="utf8mb4")
    sql = open(os.path.join(os.path.dirname(__file__), "schema.sql")).read()
    with conn.cursor() as cur:
        for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
            cur.execute(stmt)
        cur.execute("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s "
                    "AND TABLE_NAME='transfers' AND COLUMN_NAME='seq'", (config["DB_NAME"],))
        if cur.fetchone()[0] == 0:      # upgrade older databases: stable ordering for same-second transfers
            cur.execute("ALTER TABLE transfers ADD COLUMN seq BIGINT NOT NULL AUTO_INCREMENT, ADD UNIQUE KEY uq_seq (seq)")
    conn.commit()
    conn.close()
