/* Browser/Node WebCrypto implementation of the EVC1 envelope. Byte-compatible with client/envelope.py.
   Private keys are imported as NON-extractable CryptoKeys and never sent anywhere.
   Every high-level operation also returns a `timings` object (milliseconds, performance.now()). */
(function (root) {
  'use strict';
  const C = root.crypto, subtle = C.subtle, te = new TextEncoder();
  const MAGIC = te.encode('EVC1');
  const RSA_PSS = { name: 'RSA-PSS', hash: 'SHA-256' }, RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' };
  const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

  const rnd = (n) => C.getRandomValues(new Uint8Array(n));
  function concat(...a) { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; a.forEach(x => { o.set(x, p); p += x.length; }); return o; }
  const toHex = (b) => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
  function b64e(u) { let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }
  function b64d(s) { const bin = atob(s), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  const pemToDer = (pem) => b64d(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const derToPem = (der, label) => `-----BEGIN ${label}-----\n${b64e(der).match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
  const sha256 = async (u) => new Uint8Array(await subtle.digest('SHA-256', u));

  const importPrivSign = (pem, ext = false) => subtle.importKey('pkcs8', pemToDer(pem), RSA_PSS, ext, ['sign']);
  const importPrivOaep = (pem) => subtle.importKey('pkcs8', pemToDer(pem), RSA_OAEP, false, ['decrypt']);
  const importPubOaep = (pem) => subtle.importKey('spki', pemToDer(pem), RSA_OAEP, false, ['encrypt']);
  const importPubPss = (pem) => subtle.importKey('spki', pemToDer(pem), RSA_PSS, false, ['verify']);

  async function publicPemFromPrivate(privPem) {
    const k = await importPrivSign(privPem, true), j = await subtle.exportKey('jwk', k);
    const pub = await subtle.importKey('jwk', { kty: 'RSA', n: j.n, e: j.e, alg: 'PS256', ext: true }, RSA_PSS, true, ['verify']);
    return derToPem(new Uint8Array(await subtle.exportKey('spki', pub)), 'PUBLIC KEY');
  }
  const fingerprintOfPem = async (pubPem) => toHex(await sha256(pemToDer(pubPem)));

  /* Fresh RSA-2048 key pair as PEM strings (used by the self-test and the in-browser benchmark). */
  async function generateKeyPem() {
    const kp = await subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    return {
      priv: derToPem(new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey)), 'PRIVATE KEY'),
      pub: derToPem(new Uint8Array(await subtle.exportKey('spki', kp.publicKey)), 'PUBLIC KEY'),
    };
  }

  // ---------------- symmetric envelope (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC) ----------------
  async function encrypt(plain) {
    const t0 = now();
    const encKey = rnd(32), macKey = rnd(32), iv = rnd(16);
    const k = await subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['encrypt']);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, k, plain));
    const t1 = now();
    const body = concat(MAGIC, iv, ct);
    const hk = await subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const tag = new Uint8Array(await subtle.sign('HMAC', hk, body));
    const t2 = now();
    return { blob: concat(body, tag), keymat: concat(encKey, macKey), timings: { aes_ms: t1 - t0, mac_ms: t2 - t1, total_ms: t2 - t0 } };
  }
  async function decryptTimed(blob, keymat) {
    if (keymat.length !== 64) throw new Error('bad key material');
    if (blob.length < 52 || (blob.length - 52) % 16 || !MAGIC.every((b, i) => blob[i] === b)) throw new Error('malformed envelope');
    const t0 = now();
    const body = blob.subarray(0, blob.length - 32), tag = blob.subarray(blob.length - 32);
    const hk = await subtle.importKey('raw', keymat.subarray(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    if (!(await subtle.verify('HMAC', hk, tag, body))) throw new Error('MAC verification failed: ciphertext was modified or key is wrong');
    const t1 = now();
    const k = await subtle.importKey('raw', keymat.subarray(0, 32), { name: 'AES-CBC' }, false, ['decrypt']);
    const plain = new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: body.subarray(4, 20) }, k, body.subarray(20)));
    const t2 = now();
    return { plain, timings: { mac_ms: t1 - t0, aes_ms: t2 - t1, total_ms: t2 - t0 } };
  }
  const decrypt = async (blob, keymat) => (await decryptTimed(blob, keymat)).plain;

  const wrapKey = async (pubPem, keymat) => new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, await importPubOaep(pubPem), keymat));
  async function unwrapKey(privPem, wrapped) {
    try { return new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, await importPrivOaep(privPem), wrapped)); }
    catch (e) { throw new Error('cannot unwrap key: this transfer was not encrypted for your key'); }
  }
  const sign = async (privPem, msg) => new Uint8Array(await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, await importPrivSign(privPem), msg));
  const verify = async (pubPem, msg, sig) => subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, await importPubPss(pubPem), sig, msg);

  const transferMessage = (f) => te.encode(['EVSIG1', f.sender, f.recipient, f.recipientFp, f.filename, f.mime,
    String(f.size), f.ctSha256, f.wkSha256, String(f.ts), f.nonce].join('\n'));
  const popMessage = (user, fp) => te.encode(`EVKEY1\n${user}\n${fp}`);

  async function popSignature(privPem, username) {
    const fp = await fingerprintOfPem(await publicPemFromPrivate(privPem));
    return b64e(await sign(privPem, popMessage(username, fp)));
  }

  /* Encrypt + sign for a recipient. recipient = {username, fingerprint, public_key_pem} from /api/recipients.
     timings: encrypt (AES + HMAC), key wrap, hashing, signature generation, total. */
  async function buildTransfer({ username, privPem, recipient, data, filename, mime }) {
    const T0 = now();
    const enc = await encrypt(data), blob = enc.blob;
    let t = now();
    const wk = await wrapKey(recipient.public_key_pem, enc.keymat);
    const wrap_ms = now() - t;
    t = now();
    const ctSha = toHex(await sha256(blob)), wkSha = toHex(await sha256(wk));
    const hash_ms = now() - t;
    const ts = Math.floor(Date.now() / 1000), nonce = toHex(rnd(16)), mt = mime || 'application/octet-stream';
    const msg = transferMessage({ sender: username, recipient: recipient.username, recipientFp: recipient.fingerprint,
      filename, mime: mt, size: data.length, ctSha256: ctSha, wkSha256: wkSha, ts, nonce });
    t = now();
    const sig = await sign(privPem, msg);
    const sign_ms = now() - t;
    return { blob, fields: { recipient: recipient.username, recipient_key_fp: recipient.fingerprint, filename, mime_type: mt,
      size: String(data.length), timestamp: String(ts), nonce, wrapped_key: b64e(wk), signature: b64e(sig) },
      timings: { encrypt_ms: enc.timings.total_ms, aes_ms: enc.timings.aes_ms, mac_ms: enc.timings.mac_ms, wrap_ms, hash_ms, sign_ms,
        total_ms: now() - T0, plaintext_bytes: data.length, ciphertext_bytes: blob.length } };
  }

  /* Verify hash -> sender key fingerprint -> own key -> signature -> unwrap -> MAC -> decrypt.
     report.timings: hash, signature verification, key unwrap, MAC check, AES decryption, total. */
  async function openEnvelope(meta, blob, privPem) {
    const T0 = now();
    let t = now();
    const ctSha = toHex(await sha256(blob));
    const hash_ms = now() - t;
    if (ctSha !== meta.ciphertext_sha256) throw new Error('ciphertext hash does not match server metadata');
    t = now();
    if ((await fingerprintOfPem(meta.sender_public_key_pem)) !== meta.sender_key_fp) throw new Error('sender key fingerprint mismatch');
    if ((await fingerprintOfPem(await publicPemFromPrivate(privPem))) !== meta.recipient_key_fp) throw new Error('this private key is not the key the sender encrypted for');
    const check_ms = now() - t;
    const wk = b64d(meta.wrapped_key);
    const msg = transferMessage({ sender: meta.sender, recipient: meta.recipient, recipientFp: meta.recipient_key_fp, filename: meta.filename,
      mime: meta.mime_type, size: meta.size_bytes, ctSha256: ctSha, wkSha256: toHex(await sha256(wk)), ts: meta.signed_at, nonce: meta.nonce });
    t = now();
    if (!(await verify(meta.sender_public_key_pem, msg, b64d(meta.signature)))) throw new Error('sender signature invalid');
    const verify_ms = now() - t;
    t = now();
    const keymat = await unwrapKey(privPem, wk);
    const unwrap_ms = now() - t;
    const dec = await decryptTimed(blob, keymat);
    if (dec.plain.length !== meta.size_bytes) throw new Error('plaintext size differs from signed size');
    return { plain: dec.plain, report: { sender: meta.sender, senderKeyFp: meta.sender_key_fp, signatureValid: true, macValid: true,
      ciphertextSha256: ctSha, plaintextSha256: toHex(await sha256(dec.plain)),
      timings: { hash_ms, check_ms, verify_ms, unwrap_ms, mac_ms: dec.timings.mac_ms, aes_ms: dec.timings.aes_ms, decrypt_ms: dec.timings.total_ms,
        total_ms: now() - T0, plaintext_bytes: dec.plain.length, ciphertext_bytes: blob.length } } };
  }

  /* Explicit tampering experiment. Takes a transfer the receiver can open and tries to break it in
     ten different ways. Every attack must be REJECTED (detected = true) for the scheme to be sound. */
  async function tamperTest(meta, blob, privPem) {
    const out = [];
    const flip = (u, i) => { const c = u.slice(); c[i] ^= 1; return c; };
    const run = async (name, expect, fn) => {
      const t0 = now(); let detected = false, message = 'accepted: attack NOT detected';
      try { await fn(); } catch (e) { detected = true; message = e.message; }
      out.push({ name, expect, detected, message, ms: now() - t0 });
    };
    const n = blob.length, body = 20 + Math.floor(Math.max(n - 52, 1) / 2), wk = b64d(meta.wrapped_key);
    const keymat = await unwrapKey(privPem, wk);          // genuine key material for the MAC-level attacks
    const sigOk = async (m, s) => { if (!(await verify(meta.sender_public_key_pem, m, s))) throw new Error('sender signature invalid'); };
    const baseMsg = (over) => transferMessage(Object.assign({ sender: meta.sender, recipient: meta.recipient, recipientFp: meta.recipient_key_fp,
      filename: meta.filename, mime: meta.mime_type, size: meta.size_bytes, ctSha256: meta.ciphertext_sha256,
      wkSha256: '', ts: meta.signed_at, nonce: meta.nonce }, over));
    const wkSha = toHex(await sha256(wk));

    await run('Flip one bit inside the ciphertext', 'SHA-256 of the ciphertext no longer matches', () => openEnvelope(meta, flip(blob, body), privPem));
    await run('Flip one bit, skipping the hash check', 'HMAC-SHA256 tag fails before any decryption', () => decrypt(flip(blob, body), keymat));
    await run('Change the IV', 'HMAC covers the IV, so the tag fails', () => decrypt(flip(blob, 4 + 3), keymat));
    await run('Change the MAC tag', 'Tag comparison fails', () => decrypt(flip(blob, n - 1), keymat));
    await run('Cut the last 3 blocks off', 'Envelope is malformed or the tag fails', () => decrypt(blob.slice(0, Math.max(n - 48, 0)), keymat));
    await run('Corrupt the envelope header', 'Magic bytes EVC1 missing', () => decrypt(flip(blob, 0), keymat));
    await run('Corrupt the wrapped key', 'RSA-OAEP unwrap fails', () => unwrapKey(privPem, flip(wk, 10)));
    const other = await generateKeyPem();
    await run('Decrypt with a different private key', 'RSA-OAEP unwrap fails for anyone but the recipient', () => unwrapKey(other.priv, wk));
    await run('Change the signed file name', 'Sender signature no longer verifies',
      () => sigOk(baseMsg({ filename: meta.filename + '.exe', wkSha256: wkSha }), b64d(meta.signature)));
    await run('Corrupt the signature', 'Sender signature no longer verifies',
      () => sigOk(baseMsg({ wkSha256: wkSha }), flip(b64d(meta.signature), 5)));
    return out;
  }

  /* A complete throw-away transfer (two fresh RSA keys) so the tamper test and demos can run without real evidence. */
  async function selfTestBundle(data) {
    data = data || te.encode('Witness statement - case 2026/0417. I saw the vehicle at 21:40.\n'.repeat(20));
    const s = await generateKeyPem(), r = await generateKeyPem();
    const sfp = await fingerprintOfPem(s.pub), rfp = await fingerprintOfPem(r.pub);
    const bt = await buildTransfer({ username: 'demo-sender', privPem: s.priv, recipient: { username: 'demo-receiver', fingerprint: rfp, public_key_pem: r.pub },
      data, filename: 'demo_statement.txt', mime: 'text/plain' });
    const f = bt.fields;
    const meta = { id: 'demo', sender: 'demo-sender', recipient: 'demo-receiver', filename: f.filename, mime_type: f.mime_type, size_bytes: data.length,
      signed_at: Number(f.timestamp), nonce: f.nonce, signature: f.signature, wrapped_key: f.wrapped_key, recipient_key_fp: rfp, sender_key_fp: sfp,
      sender_public_key_pem: s.pub, ciphertext_sha256: toHex(await sha256(bt.blob)) };
    return { meta, blob: bt.blob, plain: data, privPem: r.priv, senderPriv: s.priv, timings: bt.timings };
  }

  const api = { b64e, b64d, toHex, sha256, publicPemFromPrivate, fingerprintOfPem, encrypt, decrypt, decryptTimed, wrapKey, unwrapKey,
    sign, verify, popSignature, buildTransfer, openEnvelope, tamperTest, selfTestBundle, generateKeyPem,
    importers: { importPrivSign, importPrivOaep, importPubOaep, importPubPss }, now };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.EVCrypto = api;
})(typeof globalThis !== 'undefined' ? globalThis : window);
