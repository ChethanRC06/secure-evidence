"""Steps 1-3: receiver authorization, per-user key management, inbox + download/decrypt."""
import base64, os, time
import pytest
from client.api import EvidenceClient, ApiError
from client import envelope as E

SECRET = b"Exhibit A: witness statement. CONFIDENTIAL.\n" * 50


def send(w, to="bob", data=SECRET, name="exhibit_a.txt", sender="alice"):
    return w.client(sender).send(w.priv[sender], to, data, name)["id"]


# ---------------- Step 1: receiver authorization ----------------
def test_intended_receiver_can_download_and_decrypt(world):
    tid = send(world)
    plain, rep = world.client("bob").receive(tid, world.priv["bob"])
    assert plain == SECRET and rep["signature_valid"] and rep["mac_valid"]


@pytest.mark.parametrize("who", ["carol", "alice", "mallory", "admin"])
def test_everyone_else_is_denied_metadata_and_ciphertext(world, who):
    tid = send(world)
    c = world.client(who)
    for path in (f"/api/transfers/{tid}", f"/api/transfers/{tid}/ciphertext"):
        with pytest.raises(ApiError) as e:
            c._req("GET", path)
        assert e.value.status == 404          # 404, not 403: don't confirm the transfer exists
    assert "AUTHZ_DENIED_TRANSFER" in world.audit_actions()


def test_receiver_isolation_in_inbox(world):
    send(world, to="bob")
    assert len(world.client("bob").inbox()) == 1
    assert world.client("carol").inbox() == []


def test_other_investigator_cannot_decrypt_even_with_stolen_ciphertext(world):
    tid = send(world)
    bob = world.client("bob")
    meta = bob._req("GET", f"/api/transfers/{tid}").json()
    blob = bob._req("GET", f"/api/transfers/{tid}/ciphertext").content
    with pytest.raises(E.IntegrityError):     # carol has the bytes but not bob's private key
        EvidenceClient.open_envelope(meta, blob, world.priv["carol"])


def test_wrapped_key_is_bound_to_bob(world):
    """Even bypassing the client's fingerprint check, carol's key cannot unwrap bob's key."""
    tid = send(world)
    bob = world.client("bob")
    meta = bob._req("GET", f"/api/transfers/{tid}").json()
    with pytest.raises(E.IntegrityError):
        E.unwrap_key(world.priv["carol"], base64.b64decode(meta["wrapped_key"]))


def test_role_enforcement(world):
    with pytest.raises(ApiError) as e:        # investigators cannot upload
        world.client("bob").send(world.priv["bob"], "carol", b"x", "x.txt")
    assert e.value.status in (403, 404)
    with pytest.raises(ApiError) as e:        # officers cannot read audit log
        world.client("alice")._req("GET", "/api/audit")
    assert e.value.status == 403


def test_unauthenticated_and_bad_token(world):
    tid = send(world)
    c = EvidenceClient(world.url)
    with pytest.raises(ApiError) as e: c._req("GET", f"/api/transfers/{tid}/ciphertext")
    assert e.value.status == 401
    c.token = "not-a-real-token"
    with pytest.raises(ApiError) as e: c.inbox()
    assert e.value.status == 401
    assert "AUTH_INVALID_TOKEN" in world.audit_actions()


def test_malformed_transfer_id_is_rejected_safely(world):
    c = world.client("bob")
    for bad in ("../../etc/passwd", "1' OR '1'='1", "z" * 32):
        with pytest.raises(ApiError) as e:
            c._req("GET", f"/api/transfers/{bad}")
        assert e.value.status == 404


# ---------------- Step 2: key management ----------------
def test_each_user_has_their_own_key_bound_to_them(world):
    recs = {r["username"]: r["fingerprint"] for r in world.client("alice").recipients()}
    assert set(recs) == {"bob", "carol"}
    assert recs["bob"] == E.fingerprint(world.priv["bob"].public_key())
    assert recs["bob"] != recs["carol"]


def test_ciphertext_is_encrypted_to_the_named_recipients_key(world):
    tid = send(world, to="carol")
    row = world.db("SELECT recipient_key_id FROM transfers WHERE id=%s", (tid,))[0]
    k = world.db("SELECT u.username FROM user_keys k JOIN users u ON u.id=k.user_id WHERE k.id=%s",
                 (row["recipient_key_id"],))[0]
    assert k["username"] == "carol"
    with pytest.raises(ApiError):             # bob cannot open carol's transfer
        world.client("bob").receive(tid, world.priv["bob"])
    plain, _ = world.client("carol").receive(tid, world.priv["carol"])
    assert plain == SECRET


def test_key_registration_requires_proof_of_possession(world):
    c = world.client("alice")
    stolen_pub = E.pub_pem(world.priv["bob"])           # try to register bob's public key as alice's
    fp = E.fingerprint(world.priv["bob"].public_key())
    sig = base64.b64encode(E.sign(world.priv["alice"], E.pop_message("alice", fp))).decode()
    with pytest.raises(ApiError) as e:
        c._req("PUT", "/api/me/key", json={"public_key_pem": stolen_pub, "pop_signature": sig})
    assert e.value.status == 400


def test_same_public_key_cannot_be_bound_to_two_users(world):
    with pytest.raises(ApiError) as e:
        world.client("carol").register_key(world.priv["bob"])
    assert e.value.status == 409


def test_key_rotation_revokes_old_key_and_stale_fingerprint_is_rejected(world):
    alice = world.client("alice")
    form, blob = alice.build_transfer(world.priv["alice"], "bob", b"data", "a.txt")   # built against bob's old key
    new_bob = E.generate_rsa()
    world.client("bob").register_key(new_bob)
    with pytest.raises(ApiError) as e:
        alice.post_transfer(form, blob)
    assert e.value.status == 409
    tid = alice.send(world.priv["alice"], "bob", b"fresh", "b.txt")["id"]
    plain, _ = world.client("bob").receive(tid, new_bob)
    assert plain == b"fresh"
    active = world.db("SELECT COUNT(*) n FROM user_keys k JOIN users u ON u.id=k.user_id "
                      "WHERE u.username='bob' AND k.revoked_at IS NULL")[0]["n"]
    assert active == 1


def test_sender_must_have_registered_key_and_signature_must_match_it(world):
    # signature made with mallory's key but submitted as alice -> rejected
    alice = world.client("alice")
    form, blob = alice.build_transfer(world.priv["mallory"], "bob", b"forged", "f.txt")
    with pytest.raises(ApiError) as e:
        alice.post_transfer(form, blob)
    assert e.value.status == 400 and "signature" in e.value.msg
    assert "UPLOAD_REJECTED_BAD_SIGNATURE" in world.audit_actions()


def test_replay_and_stale_timestamp_rejected(world):
    alice = world.client("alice")
    form, blob = alice.build_transfer(world.priv["alice"], "bob", b"once", "o.txt")
    alice.post_transfer(form, blob)
    with pytest.raises(ApiError) as e:
        alice.post_transfer(form, blob)                  # exact replay
    assert e.value.status == 409
    form2, blob2 = alice.build_transfer(world.priv["alice"], "bob", b"old", "old.txt", ts=int(time.time()) - 3600)
    with pytest.raises(ApiError) as e:
        alice.post_transfer(form2, blob2)
    assert e.value.status == 400


# ---------------- Step 3: inbox / download / decrypt ----------------
def test_inbox_lists_only_my_files_and_marks_downloaded(world):
    t1, t2 = send(world, name="one.txt"), send(world, to="carol", name="two.txt")
    inbox = world.client("bob").inbox()
    assert [t["filename"] for t in inbox] == ["one.txt"] and inbox[0]["sender"] == "alice"
    assert inbox[0]["downloaded_at"] is None
    world.client("bob").receive(t1, world.priv["bob"])
    assert world.client("bob").inbox()[0]["downloaded_at"] is not None
    assert [t["filename"] for t in world.client("alice").sent()] == ["two.txt", "one.txt"]


def test_server_never_stores_plaintext(world):
    tid = send(world)
    stored = open(os.path.join(world.cfg["STORAGE_DIR"], tid + ".bin"), "rb").read()
    assert b"WITNESS" not in stored.upper() and b"CONFIDENTIAL" not in stored
    assert stored[:4] == b"EVC1"
