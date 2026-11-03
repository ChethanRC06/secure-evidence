"""Step 4: text + image + audio (.wav/.mp3) + video + document, through BOTH the Python client and the
browser-crypto (Node) path, in both directions. Decrypted media must be byte-identical AND still decodable."""
import hashlib, json, os, subprocess, sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from make_samples import make
from client import envelope as E
from test_step3_browser_interop import node

CASES = ["witness_statement.txt", "crime_scene.png", "crime_scene.jpg", "interview.wav",
         "voicemail.mp3", "cctv_clip.mp4", "report.pdf"]


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("samples")); make(out)
    return out


@pytest.fixture()
def keyfiles(world, tmp_path):
    out = {}
    for n in ("alice", "bob"):
        p = tmp_path / f"{n}.pem"; p.write_bytes(E.priv_pem(world.priv[n])); out[n] = str(p)
    return out


def decodable(path):
    if path.endswith((".wav", ".mp3", ".mp4")):
        r = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-f", "null", "-"], capture_output=True, text=True)
        return r.returncode == 0 and not r.stderr.strip()
    if path.endswith((".png", ".jpg")):
        from PIL import Image; Image.open(path).load(); return True
    return True


@pytest.mark.parametrize("name", CASES)
def test_python_roundtrip(world, samples, tmp_path, name):
    data = open(os.path.join(samples, name), "rb").read()
    tid = world.client("alice").send(world.priv["alice"], "bob", data, name)["id"]
    inbox = world.client("bob").inbox()[0]
    plain, rep = world.client("bob").receive(tid, world.priv["bob"])
    assert plain == data and hashlib.sha256(plain).hexdigest() == hashlib.sha256(data).hexdigest()
    out = tmp_path / name; out.write_bytes(plain)
    assert decodable(str(out))
    assert inbox["category"] in ("text", "image", "audio", "video", "document")


@pytest.mark.parametrize("name", CASES)
def test_browser_js_roundtrip_both_directions(world, samples, keyfiles, tmp_path, name):
    src = os.path.join(samples, name); data = open(src, "rb").read()
    # Python -> JS
    tid = world.client("alice").send(world.priv["alice"], "bob", data, name)["id"]
    out = tmp_path / ("js_" + name)
    rc, _, se = node("receive", world.url, "bob", "bob-Passw0rd!", keyfiles["bob"], tid, str(out))
    assert rc == 0, se
    assert out.read_bytes() == data and decodable(str(out))
    # JS -> Python
    rc, so, se = node("send", world.url, "alice", "alice-Passw0rd!", keyfiles["alice"], "bob", src)
    assert rc == 0, se
    plain, _ = world.client("bob").receive(json.loads(so)["id"], world.priv["bob"])
    assert plain == data


def test_categories_assigned(world, samples):
    alice = world.client("alice")
    for n in CASES:
        alice.send(world.priv["alice"], "bob", open(os.path.join(samples, n), "rb").read(), n)
    got = {t["filename"]: t["category"] for t in world.client("bob").inbox()}
    assert got == {"witness_statement.txt": "text", "crime_scene.png": "image", "crime_scene.jpg": "image",
                   "interview.wav": "audio", "voicemail.mp3": "audio", "cctv_clip.mp4": "video", "report.pdf": "document"}


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 4095, 4096])     # AES block / PKCS7 padding boundaries
def test_padding_boundaries(world, n):
    data = os.urandom(n)
    tid = world.client("alice").send(world.priv["alice"], "bob", data, f"b{n}.bin")["id"]
    assert world.client("bob").receive(tid, world.priv["bob"])[0] == data


def test_unicode_filename(world):
    name = "证据_déclaration_📎.txt"
    tid = world.client("alice").send(world.priv["alice"], "bob", b"hello", name)["id"]
    plain, rep = world.client("bob").receive(tid, world.priv["bob"])
    assert plain == b"hello" and rep["filename"] == name


def test_large_video_sized_file_30MB(world, keyfiles, tmp_path):
    data = os.urandom(30 * 1024 * 1024)
    tid = world.client("alice").send(world.priv["alice"], "bob", data, "big.mp4")["id"]
    assert world.client("bob").receive(tid, world.priv["bob"])[0] == data
    out = tmp_path / "big_js.mp4"
    rc, _, se = node("receive", world.url, "bob", "bob-Passw0rd!", keyfiles["bob"], tid, str(out))
    assert rc == 0, se
    assert hashlib.sha256(out.read_bytes()).digest() == hashlib.sha256(data).digest()


def test_upload_over_limit_rejected(world):
    import requests
    c = world.client("alice")
    r = requests.post(world.url + "/api/transfers", headers={"Authorization": f"Bearer {c.token}"},
                      files={"ciphertext": ("x", b"\0" * (101 * 1024 * 1024))}, data={"recipient": "bob"})
    assert r.status_code == 413
