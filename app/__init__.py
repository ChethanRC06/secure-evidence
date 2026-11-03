import os, logging
import pymysql
from werkzeug.exceptions import HTTPException
from flask import Flask, g, jsonify, request, send_from_directory
from .db import close_db
from .limiter import limiter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_config():
    e = os.environ.get
    return dict(
        DB_HOST=e("DB_HOST", "127.0.0.1"), DB_PORT=int(e("DB_PORT", "3306")),
        DB_USER=e("DB_USER", "evidence"), DB_PASSWORD=e("DB_PASSWORD", "evidence_pw"),
        DB_NAME=e("DB_NAME", "evidence_db"),
        STORAGE_DIR=e("STORAGE_DIR", os.path.join(ROOT, "storage")),
        REPORT_DIR=e("REPORT_DIR", os.path.join(ROOT, "report")),
        MAX_CONTENT_LENGTH=int(e("MAX_UPLOAD_MB", "100")) * 1024 * 1024,
        LOGIN_RATE=e("LOGIN_RATE", "10 per minute"),
    )


def create_app(overrides=None):
    app = Flask(__name__, static_folder=os.path.join(ROOT, "static"), static_url_path="/static")
    app.config.update(default_config())
    app.config.update(overrides or {})
    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    limiter.init_app(app)

    from . import auth, transfers, metrics
    app.register_blueprint(auth.bp)
    app.register_blueprint(transfers.bp)
    app.register_blueprint(metrics.bp)
    app.teardown_appcontext(close_db)

    @app.after_request
    def finish(resp):
        if "db" in g:   # commit audit rows even for 4xx; roll back on server errors
            (g.db.commit if resp.status_code < 500 else g.db.rollback)()
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; frame-ancestors 'none'"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if resp.mimetype == "application/json":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="file too large"), 413

    @app.errorhandler(429)
    def rate_limited(_):
        return jsonify(error="rate limit exceeded"), 429

    @app.errorhandler(Exception)
    def unexpected(e):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled error on %s", request.path)
        if isinstance(e, pymysql.err.Error):
            from .bootstrap import explain
            msg = "Database problem: " + explain(e, app.config)
        else:
            msg = "Internal server error (details are in the server console)."
        return jsonify(error=msg), 500

    @app.get("/api/health")
    def health():
        from .db import query
        try:
            n = query("SELECT COUNT(*) AS n FROM users", one=True)["n"]
        except pymysql.err.Error as e:
            from .bootstrap import explain
            return jsonify(ok=False, error=explain(e, app.config)), 503
        return jsonify(ok=True, users=n)

    return app
