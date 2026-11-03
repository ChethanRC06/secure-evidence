"""Public-key parsing, fingerprints, and signature verification (server side).
The server only ever handles PUBLIC keys."""
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


def parse_public_key(pem: str):
    key = serialization.load_pem_public_key(pem.encode())
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise ValueError("RSA key must be >= 2048 bits")
        return key, "RSA"
    raise ValueError("unsupported key type")


def fingerprint(key) -> str:
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def verify(key, message: bytes, signature: bytes) -> bool:
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                       hashes.SHA256())
            return True
    except InvalidSignature:
        return False
    return False


def transfer_message(sender, recipient, recipient_fp, filename, mime, size,
                     ct_sha256, wk_sha256, ts, nonce) -> bytes:
    """Canonical byte string the sender signs (identical in Python and JS)."""
    lines = ["EVSIG1", sender, recipient, recipient_fp, filename, mime, str(size),
             ct_sha256, wk_sha256, str(ts), nonce]
    return "\n".join(lines).encode("utf-8")


def pop_message(username, fp) -> bytes:
    """Proof-of-possession: user signs this with the new private key when registering a public key."""
    return f"EVKEY1\n{username}\n{fp}".encode()
