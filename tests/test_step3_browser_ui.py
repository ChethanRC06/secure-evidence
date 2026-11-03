"""Real-browser (headless Chromium) test of the web UI: send as Alice, receive/decrypt as Bob, Carol sees nothing."""
import io, os
import pytest
from PIL import Image
from client import envelope as E

pw = pytest.importorskip("playwright.sync_api")
SHOTS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "report", "screenshots")


@pytest.fixture()
def keyfiles(world, tmp_path):
    out = {}
    for n in ("alice", "bob", "carol"):
        p = tmp_path / f"{n}.pem"; p.write_bytes(E.priv_pem(world.priv[n])); out[n] = str(p)
    return out


def login(page, url, user):
    page.goto(url)
    page.fill("input[type=text]", user); page.fill("input[type=password]", f"{user}-Passw0rd!")
    page.click("text=Sign in >> nth=-1"); page.wait_for_selector("text=My key")


def test_browser_send_and_receive(world, keyfiles, tmp_path):
    img = io.BytesIO(); Image.new("RGB", (320, 200), (30, 90, 200)).save(img, "PNG")
    png = tmp_path / "scene_photo.png"; png.write_bytes(img.getvalue())
    os.makedirs(SHOTS, exist_ok=True)
    with pw.sync_playwright() as p:
        b = p.chromium.launch(); errors = []
        def new_page():
            pg = b.new_context(viewport={"width": 1000, "height": 800}).new_page()
            pg.on("pageerror", lambda e: errors.append(str(e))); return pg

        # --- Alice sends ---
        a = new_page(); login(a, world.url, "alice")
        a.set_input_files("input[accept='.pem']", keyfiles["alice"]); a.wait_for_selector("text=Key loaded")
        a.select_option("select", "bob"); a.set_input_files("input[type=file] >> nth=-1", str(png))
        a.click("text=Encrypt & send"); a.wait_for_selector("text=Sent. Transfer")
        a.screenshot(path=os.path.join(SHOTS, "01_officer_send.png"))

        # --- Carol (wrong receiver) sees nothing ---
        c = new_page(); login(c, world.url, "carol"); c.wait_for_selector("text=No evidence has been sent to you")
        c.screenshot(path=os.path.join(SHOTS, "02_other_investigator_empty_inbox.png"))

        # --- Bob receives, decrypts, previews ---
        d = new_page(); login(d, world.url, "bob")
        d.wait_for_selector("text=scene_photo.png")
        d.set_input_files("input[accept='.pem']", keyfiles["bob"]); d.wait_for_selector("text=Key loaded")
        d.click("text=Download & decrypt"); d.wait_for_selector("text=Verified: scene_photo.png")
        assert d.locator("text=sender signature valid").count() == 1
        assert d.eval_on_selector(".preview img", "i => i.complete && i.naturalWidth") == 320
        d.screenshot(path=os.path.join(SHOTS, "03_investigator_decrypted_image.png"))

        # --- Bob loads Carol's key: must fail, not decrypt ---
        e = new_page(); login(e, world.url, "bob"); e.wait_for_selector("text=scene_photo.png")
        e.set_input_files("input[accept='.pem']", keyfiles["carol"]); e.wait_for_selector("text=Key loaded")
        e.click("text=Download & decrypt"); e.wait_for_selector("text=FAILED")
        assert "not the key the sender encrypted for" in e.inner_text("#app")
        e.screenshot(path=os.path.join(SHOTS, "04_wrong_key_rejected.png"))
        b.close()
    assert not errors, errors
