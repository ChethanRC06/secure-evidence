import os, sys
from app import create_app, default_config
from app.bootstrap import bootstrap

ok, msg = bootstrap(default_config())
print(("[setup] " if ok else "[setup FAILED] ") + msg)
if not ok:
    print("\nThe server will still start, but login will fail until this is fixed.\n")

app = create_app()
if __name__ == "__main__":
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "5000")),
            ssl_context=(cert, key) if cert and key else None)
