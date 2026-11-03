# Secure Digital Evidence Transfer System

Officer (sender) → server → Investigator (receiver). The server stores **only ciphertext**; plaintext and
private keys never leave the client (browser tab or Python client).

## Cryptographic design
| Purpose | Mechanism |
|---|---|
| File confidentiality | **AES-256-CBC** + **HMAC-SHA256** (encrypt-then-MAC), independent random enc/MAC keys per file |
| Key transport | enc‖mac keys (64 B) wrapped with the **recipient's own RSA-2048 public key** (OAEP, SHA-256) |
| Authenticity / non-repudiation | Sender signs (RSA-PSS, SHA-256) a canonical message binding sender, recipient, recipient key fingerprint, filename, MIME, size, ciphertext hash, wrapped-key hash, timestamp, nonce |
| Replay protection | ±300 s timestamp window + per-sender unique nonce (DB unique constraint) |
| Chain of custody | Hash-chained audit log (each row commits to the previous row's hash) |

Envelope: `"EVC1" ‖ IV(16) ‖ ciphertext ‖ HMAC(32)`. The MAC is verified in constant time **before** decryption.

## Authorization & key management (steps 1–2)
* Every user has their own key pair; the server stores public keys only (`user_keys`), bound to the user.
* Registering a key requires **proof of possession** (signature with the matching private key); a public key
  can't be bound to two users; rotating a key revokes the old one.
* Receiver authorization has a single choke point (`_recipient_transfer`): only `recipient_id == caller`
  can fetch metadata/ciphertext. Everyone else (other investigators, the sender, other officers, admin) gets
  **404** and an `AUTHZ_DENIED_TRANSFER` audit entry. Even stolen ciphertext is useless without Bob's private key.
* Roles: `officer` (send), `investigator` (receive), `admin` (users + audit; cannot read evidence).

## Run
```bash
pip install -r requirements.txt
mysql -uroot -e "CREATE DATABASE evidence_db CHARACTER SET utf8mb4;
  CREATE USER 'evidence'@'localhost' IDENTIFIED BY 'evidence_pw'; GRANT ALL ON evidence_db.* TO 'evidence'@'localhost';"
python run.py                         # first start auto-creates the database, tables and demo users (password: <username>-Passw0rd!)
# python scripts/setup_db.py          # optional: same setup without starting the server
#                        # http://localhost:5000   (TLS: TLS_CERT=... TLS_KEY=... python run.py)
python -m client.cli keygen alice     # writes keys/alice.pem (PKCS#8) – do this for alice and bob
```
Open the web UI, sign in, load your private key file, click **Register / rotate my public key** once, then
officers use **Send evidence**; investigators use the **Inbox** (download → verify → decrypt → preview/save).
Env vars: `DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME STORAGE_DIR MAX_UPLOAD_MB LOGIN_RATE`.

## Troubleshooting
* `python run.py` prints `[setup] ...` on start. If it says `[setup FAILED]`, the message tells you what to fix
  (wrong DB password, MySQL not running, missing permissions). `http://localhost:5000/api/health` shows the same.
* Login errors now show the real cause in the login box instead of a bare "Internal Server Error".
* PowerShell env vars: `$env:DB_USER="u"; $env:DB_PASSWORD="p"; python run.py`

## Tests
```bash
mysql -uroot -e "CREATE DATABASE evidence_test; GRANT ALL ON evidence_test.* TO 'evidence'@'localhost';"
python scripts/make_samples.py        # real txt/png/jpg/wav/mp3/mp4/pdf samples (needs ffmpeg)
pytest tests -q                       # needs node (browser-crypto interop) and playwright chromium (UI test)
```
| File | Covers |
|---|---|
| `test_step1_3_authorization_keys_inbox.py` | receiver isolation, roles, bad token, key binding/PoP/rotation, replay, inbox |
| `test_step3_browser_interop.py` | WebCrypto (Node) ↔ Python byte-compatibility, wrong-key rejection |
| `test_step3_browser_ui.py` | headless Chromium: Alice sends, Bob decrypts & previews, Carol blind, wrong key fails (screenshots → `report/screenshots/`) |
| `test_step4_multimedia.py` | text/PNG/JPG/WAV/MP3/MP4/PDF both directions, padding boundaries, unicode names, 30 MB file, size limit |

## Status against the plan
- [x] 1 Receiver authorization  - [x] 2 Per-user key management  - [x] 3 Inbox + browser decrypt  - [x] 4 Multimedia (.mp3/.wav)
- [ ] 5 Explicit ciphertext-tampering test  - [ ] 6 ECC secp256r1 + RSA-vs-ECC  - [ ] 7 Two-laptop LAN run
- [ ] 8 Performance instrumentation  - [ ] 9 Wireshark/PyShark  - [ ] 10 Final security suite, tables, graphs

## Known limitations (be honest in the report)
* **Key directory trust:** a malicious server could substitute a recipient's public key. Mitigation: users
  compare displayed fingerprints out-of-band; `open_envelope(..., pinned_sender_fps=...)` supports pinning.
* Filename, MIME type, size and timestamps are metadata visible to the server (not encrypted).
* The private key is loaded from a PEM file (unencrypted PKCS#8). Passphrase protection is a possible extension.
* Auth tokens live in `sessionStorage`; the CSP forbids inline/remote scripts to limit XSS exposure.
