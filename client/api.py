"""HTTP client for the evidence server (used by the CLI, tests and benchmarks)."""
import base64, hashlib, mimetypes, os, time
import requests
from . import envelope as E


class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"HTTP {status}: {msg}")
        self.status, self.msg = status, msg


class EvidenceClient:
    def __init__(self, base_url, verify=True, timeout=120):
        self.base, self.verify, self.timeout, self.token, self.username = base_url.rstrip("/"), verify, timeout, None, None
        self.last_timings = {}          # milliseconds for the most recent send/receive on this client

    def _req(self, method, path, **kw):
        h = kw.pop("headers", {})
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        r = requests.request(method, self.base + path, headers=h, verify=self.verify, timeout=self.timeout, **kw)
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except ValueError:
                msg = r.text[:200]
            raise ApiError(r.status_code, msg)
        return r

    def login(self, username, password):
        d = self._req("POST", "/api/login", json={"username": username, "password": password}).json()
        self.token, self.username = d["token"], username
        return d

    def register_key(self, priv):
        pem = E.pub_pem(priv)
        fp = E.fingerprint(priv.public_key())
        sig = base64.b64encode(E.sign(priv, E.pop_message(self.username, fp))).decode()
        return self._req("PUT", "/api/me/key", json={"public_key_pem": pem, "pop_signature": sig}).json()

    def recipients(self):
        return self._req("GET", "/api/recipients").json()["recipients"]

    def inbox(self):
        return self._req("GET", "/api/inbox").json()["transfers"]

    def sent(self):
        return self._req("GET", "/api/sent").json()["transfers"]

    # ----- send -----
    def build_transfer(self, priv, recipient, data: bytes, filename, mime=None, ts=None, nonce=None):
        """Encrypt + sign locally. Returns (form_fields, ciphertext_blob)."""
        rec = next((r for r in self.recipients() if r["username"] == recipient), None)
        if not rec:
            raise ApiError(404, f"recipient '{recipient}' not found or has no registered key")
        pc = time.perf_counter
        T0 = pc()
        rpub = E.load_public(rec["public_key_pem"])
        t = pc(); blob, keymat = E.encrypt(data); encrypt_ms = (pc() - t) * 1000
        t = pc(); wk = E.wrap_key(rpub, keymat); wrap_ms = (pc() - t) * 1000
        mime = mime or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        ts = int(time.time()) if ts is None else ts
        nonce = os.urandom(16).hex() if nonce is None else nonce
        t = pc(); ct_sha, wk_sha = hashlib.sha256(blob).hexdigest(), hashlib.sha256(wk).hexdigest(); hash_ms = (pc() - t) * 1000
        msg = E.transfer_message(self.username, recipient, rec["fingerprint"], filename, mime, len(data),
                                 ct_sha, wk_sha, ts, nonce)
        t = pc(); sig = E.sign(priv, msg); sign_ms = (pc() - t) * 1000
        form = dict(recipient=recipient, recipient_key_fp=rec["fingerprint"], filename=filename, mime_type=mime,
                    size=str(len(data)), timestamp=str(ts), nonce=nonce,
                    wrapped_key=base64.b64encode(wk).decode(),
                    signature=base64.b64encode(sig).decode())
        self.last_timings = dict(encrypt_ms=encrypt_ms, wrap_ms=wrap_ms, hash_ms=hash_ms, sign_ms=sign_ms,
                                 total_ms=(pc() - T0) * 1000, plaintext_bytes=len(data), ciphertext_bytes=len(blob))
        return form, blob

    def post_transfer(self, form, blob):
        return self._req("POST", "/api/transfers", data=form,
                         files={"ciphertext": ("evidence.bin", blob, "application/octet-stream")}).json()

    def send(self, priv, recipient, data, filename, mime=None):
        form, blob = self.build_transfer(priv, recipient, data, filename, mime)
        t = time.perf_counter()
        res = self.post_transfer(form, blob)
        self.last_timings["transfer_ms"] = (time.perf_counter() - t) * 1000      # upload round trip
        return res

    def report_metrics(self, transfer_id, kind, timings=None):
        """Tell the server how long this side's crypto took (shown on the Performance tab)."""
        keys = ("encrypt_ms", "decrypt_ms", "aes_ms", "mac_ms", "hash_ms", "wrap_ms", "unwrap_ms", "sign_ms",
                "verify_ms", "total_ms", "transfer_ms", "plaintext_bytes", "ciphertext_bytes")
        body = {k: v for k, v in (timings or self.last_timings).items() if k in keys}
        return self._req("POST", "/api/metrics", json=dict(body, transfer_id=transfer_id, kind=kind)).json()

    # ----- receive -----
    def receive(self, tid, priv, pinned_sender_fps=None):
        """Fetch, verify (hash, signature, MAC) and decrypt. Returns (plaintext, report)."""
        meta = self._req("GET", f"/api/transfers/{tid}").json()
        t = time.perf_counter()
        blob = self._req("GET", f"/api/transfers/{tid}/ciphertext").content
        download_ms = (time.perf_counter() - t) * 1000
        plain, rep = self.open_envelope(meta, blob, priv, pinned_sender_fps)
        rep["timings"]["transfer_ms"] = download_ms
        self.last_timings = rep["timings"]
        return plain, rep

    @staticmethod
    def open_envelope(meta, blob, priv, pinned_sender_fps=None):
        pc = time.perf_counter
        T0 = pc()
        t = pc(); ct_sha = hashlib.sha256(blob).hexdigest(); hash_ms = (pc() - t) * 1000
        if ct_sha != meta["ciphertext_sha256"]:
            raise E.IntegrityError("ciphertext hash does not match server metadata")
        spub = E.load_public(meta["sender_public_key_pem"])
        if E.fingerprint(spub) != meta["sender_key_fp"]:
            raise E.IntegrityError("sender key fingerprint mismatch")
        if pinned_sender_fps and pinned_sender_fps.get(meta["sender"]) not in (None, meta["sender_key_fp"]):
            raise E.IntegrityError("sender key does not match pinned fingerprint")
        if E.fingerprint(priv.public_key()) != meta["recipient_key_fp"]:
            raise E.IntegrityError("this private key is not the key the sender encrypted for")
        wk = base64.b64decode(meta["wrapped_key"])
        msg = E.transfer_message(meta["sender"], meta["recipient"], meta["recipient_key_fp"], meta["filename"],
                                 meta["mime_type"], meta["size_bytes"], ct_sha, hashlib.sha256(wk).hexdigest(),
                                 meta["signed_at"], meta["nonce"])
        t = pc(); sig_ok = E.verify(spub, msg, base64.b64decode(meta["signature"])); verify_ms = (pc() - t) * 1000
        if not sig_ok:
            raise E.IntegrityError("sender signature invalid")
        t = pc(); keymat = E.unwrap_key(priv, wk); unwrap_ms = (pc() - t) * 1000
        t = pc(); plain = E.decrypt(blob, keymat); decrypt_ms = (pc() - t) * 1000      # MAC check + AES-CBC
        if len(plain) != meta["size_bytes"]:
            raise E.IntegrityError("plaintext size differs from signed size")
        timings = dict(hash_ms=hash_ms, verify_ms=verify_ms, unwrap_ms=unwrap_ms, decrypt_ms=decrypt_ms,
                       total_ms=(pc() - T0) * 1000, plaintext_bytes=len(plain), ciphertext_bytes=len(blob))
        return plain, dict(sender=meta["sender"], sender_key_fp=meta["sender_key_fp"], signature_valid=True,
                           mac_valid=True, ciphertext_sha256=ct_sha, plaintext_sha256=hashlib.sha256(plain).hexdigest(),
                           filename=meta["filename"], size=len(plain), timings=timings)
