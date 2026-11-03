"""Client-side cryptography. Private keys and plaintext never leave the client.

Envelope (ciphertext blob):  b"EVC1" || IV(16) || AES-256-CBC(PKCS7(plaintext)) || HMAC-SHA256 tag(32)
  - Encrypt-then-MAC: tag = HMAC(mac_key, b"EVC1" || IV || ciphertext). Verified (constant time)
    BEFORE any decryption, so tampered ciphertext is rejected without being decrypted.
  - enc_key and mac_key are independent random 256-bit keys, per file.
Key transport: enc_key||mac_key (64 bytes) wrapped with the recipient's RSA public key (OAEP, SHA-256).
Authenticity:  sender signs (RSA-PSS, SHA-256) a canonical message that binds sender, recipient,
               recipient key fingerprint, file metadata, ciphertext hash, wrapped-key hash, timestamp, nonce.
"""
import hashlib, hmac, os, time
from cryptography.hazmat.primitives import hashes, serialization, padding as sympad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

MAGIC = b"EVC1"


class IntegrityError(Exception):
    """Ciphertext/MAC/signature verification failed."""


# ---------- keys ----------
def generate_rsa(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def pub_pem(priv) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def priv_pem(priv) -> bytes:   # PKCS#8, importable by WebCrypto
    return priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())


def load_private(path):
    return serialization.load_pem_private_key(open(path, "rb").read(), password=None)


def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def fingerprint(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


# ---------- symmetric envelope ----------
def encrypt(plaintext: bytes):
    enc_key, mac_key, iv = os.urandom(32), os.urandom(32), os.urandom(16)
    padder = sympad.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padder.update(plaintext) + padder.finalize()) + enc.finalize()
    body = MAGIC + iv + ct
    return body + hmac.new(mac_key, body, hashlib.sha256).digest(), enc_key + mac_key


def decrypt(blob: bytes, keymat: bytes) -> bytes:
    if len(keymat) != 64:
        raise IntegrityError("bad key material length")
    if blob[:4] != MAGIC or len(blob) < 4 + 16 + 16 + 32 or (len(blob) - 52) % 16:
        raise IntegrityError("malformed envelope")
    body, tag = blob[:-32], blob[-32:]
    if not hmac.compare_digest(tag, hmac.new(keymat[32:], body, hashlib.sha256).digest()):
        raise IntegrityError("MAC verification failed: ciphertext was modified or key is wrong")
    iv, ct = body[4:20], body[20:]
    dec = Cipher(algorithms.AES(keymat[:32]), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unp = sympad.PKCS7(128).unpadder()
    return unp.update(padded) + unp.finalize()


# ---------- key wrapping / signing ----------
_OAEP = lambda: padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def wrap_key(recipient_pub, keymat: bytes) -> bytes:
    return recipient_pub.encrypt(keymat, _OAEP())


def unwrap_key(priv, wrapped: bytes) -> bytes:
    try:
        return priv.decrypt(wrapped, _OAEP())
    except ValueError:
        raise IntegrityError("cannot unwrap key: this transfer was not encrypted for your key")


def sign(priv, message: bytes) -> bytes:
    return priv.sign(message, _PSS(), hashes.SHA256())


def verify(pub, message: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, message, _PSS(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def transfer_message(sender, recipient, recipient_fp, filename, mime, size, ct_sha256, wk_sha256, ts, nonce):
    lines = ["EVSIG1", sender, recipient, recipient_fp, filename, mime, str(size),
             ct_sha256, wk_sha256, str(ts), nonce]
    return "\n".join(lines).encode("utf-8")


def pop_message(username, fp):
    return f"EVKEY1\n{username}\n{fp}".encode()
