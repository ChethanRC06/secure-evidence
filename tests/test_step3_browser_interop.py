"""The browser's WebCrypto code (run under Node) must interoperate byte-for-byte with the Python client."""
import hashlib, json, os, subprocess
import pytest
from client import envelope as E

JS = os.path.join(os.path.dirname(__file__), "js_interop.js")


def node(*args):
    r = subprocess.run(["node", JS, *args], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


@pytest.fixture()
def keyfiles(world, tmp_path):
    out = {}
    for n in ("alice", "bob", "carol"):
        p = tmp_path / f"{n}.pem"; p.write_bytes(E.priv_pem(world.priv[n])); out[n] = str(p)
    return out


def test_python_sends_browser_js_receives(world, keyfiles, tmp_path):
    data = os.urandom(300_000)
    tid = world.client("alice").send(world.priv["alice"], "bob", data, "blob.bin")["id"]
    out = tmp_path / "out.bin"
    rc, so, se = node("receive", world.url, "bob", "bob-Passw0rd!", keyfiles["bob"], tid, str(out))
    assert rc == 0, se
    assert out.read_bytes() == data and json.loads(so)["signatureValid"]


def test_browser_js_sends_python_receives(world, keyfiles, tmp_path):
    src = tmp_path / "evidence.txt"; src.write_bytes("Ünïcödé statement ✓\n".encode() * 1000)
    rc, so, se = node("send", world.url, "alice", "alice-Passw0rd!", keyfiles["alice"], "bob", str(src))
    assert rc == 0, se
    tid = json.loads(so)["id"]
    plain, rep = world.client("bob").receive(tid, world.priv["bob"])
    assert plain == src.read_bytes() and rep["signature_valid"]


def test_js_receiver_rejects_wrong_key(world, keyfiles, tmp_path):
    tid = world.client("alice").send(world.priv["alice"], "bob", b"secret", "s.txt")["id"]
    rc, _, se = node("receive", world.url, "bob", "bob-Passw0rd!", keyfiles["carol"], tid, str(tmp_path / "x"))
    assert rc != 0 and "not the key" in se
