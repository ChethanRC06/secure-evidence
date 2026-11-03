"""Create database/tables and seed demo users (admin, alice, mallory, bob, carol). Safe to re-run."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import default_config
from app.bootstrap import bootstrap

ok, msg = bootstrap(default_config())
print(("OK: " if ok else "FAILED: ") + msg)
if ok:
    print("Demo password pattern: <username>-Passw0rd!  (override e.g. ALICE_PASSWORD=...)")
sys.exit(0 if ok else 1)
