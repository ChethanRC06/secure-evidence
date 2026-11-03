(function () {
  'use strict';
  const E = window.EVCrypto, app = document.getElementById('app'), who = document.getElementById('who');
  const S = { token: sessionStorage.getItem('ev_token'), user: sessionStorage.getItem('ev_user'), role: sessionStorage.getItem('ev_role'), privPem: null };

  // ---- tiny DOM helper (always textContent: no HTML injection from server data) ----
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (v == null || v === false) continue; if (k === 'class') n.className = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v); }
    kids.flat().forEach(c => n.append(c instanceof Node ? c : document.createTextNode(c ?? '')));
    return n;
  }
  const card = (title, ...kids) => el('div', { class: 'card' }, el('h2', {}, title), ...kids);
  const cardX = (cls, title, ...kids) => el('div', { class: 'card ' + cls }, el('h2', {}, title), ...kids);
  const fmt = (t) => t ? new Date(t * 1000).toLocaleString() : '—';
  const size = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n > 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B';
  const note = (box, text, cls) => { box.replaceChildren(el('div', { class: 'msg ' + (cls || '') }, text)); };

  async function api(path, opts = {}) {
    opts.headers = Object.assign({}, opts.headers, S.token ? { Authorization: 'Bearer ' + S.token } : {});
    const r = await fetch(path, opts);
    if (r.status === 401 && S.token) { logout(); throw new Error('Session expired'); }
    if (!r.ok) { let m = r.statusText; try { m = (await r.json()).error || m; } catch (e) {} throw new Error(m); }
    return r;
  }
  const jpost = (p, b, m = 'POST') => api(p, { method: m, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());

  function logout() { sessionStorage.clear(); S.token = S.user = S.role = S.privPem = S.view = null; render(); }

  // ---- private key loader (kept in memory only; never uploaded) ----
  function keyPanel() {
    const status = el('div', { class: 'muted' }, S.privPem ? 'Private key loaded in memory.' : 'No private key loaded.');
    const input = el('input', { type: 'file', accept: '.pem' });
    input.addEventListener('change', async () => {
      try {
        const pem = await input.files[0].text(); await E.publicPemFromPrivate(pem); S.privPem = pem;
        const fp = await E.fingerprintOfPem(await E.publicPemFromPrivate(pem));
        status.replaceChildren('Key loaded. Fingerprint: ', el('span', { class: 'mono' }, fp));
      } catch (e) { S.privPem = null; status.replaceChildren(el('span', { class: 'bad' }, 'Not a valid PKCS#8 private key PEM.')); }
    });
    const out = el('div');
    const reg = el('button', { class: 'ghost', onclick: async () => {
      if (!S.privPem) return note(out, 'Load your private key first.', 'bad');
      try {
        const pub = await E.publicPemFromPrivate(S.privPem), fp = await E.fingerprintOfPem(pub);
        await jpost('/api/me/key', { public_key_pem: pub, pop_signature: await E.popSignature(S.privPem, S.user) }, 'PUT');
        note(out, 'Public key registered for ' + S.user + ' (' + fp.slice(0, 16) + '…).', 'ok');
      } catch (e) { note(out, e.message, 'bad'); }
    } }, 'Register / rotate my public key');
    return card('My key', el('p', { class: 'muted' }, 'Your private key stays in this browser tab. Only the public key is sent to the server.'),
      el('label', {}, 'Private key file (PKCS#8 PEM)'), input, status, el('div', { class: 'row' }, reg), out);
  }

  // ---- officer: send ----
  async function sendPanel() {
    const out = el('div'), sel = el('select'), file = el('input', { type: 'file' });
    let rcps = [];
    try { rcps = (await api('/api/recipients').then(r => r.json())).recipients; } catch (e) { out.append(e.message); }
    rcps.forEach(r => sel.append(el('option', { value: r.username }, `${r.username}  (key ${r.fingerprint.slice(0, 12)}…)`)));
    if (!rcps.length) out.append(el('div', { class: 'msg bad' }, 'No recipients available yet. Each investigator must sign in, load their private key, and click "Register / rotate my public key" first; then refresh this page.'));
    const reportBox = el('div');
    const btn = el('button', { onclick: async () => {
      if (!S.privPem) return note(out, 'Load your private key first.', 'bad');
      if (!file.files[0] || !sel.value) return note(out, 'Choose a recipient and a file.', 'bad');
      btn.disabled = true; note(out, 'Encrypting and signing in your browser…'); reportBox.replaceChildren();
      try {
        const f = file.files[0], data = new Uint8Array(await f.arrayBuffer());
        const { fields, blob, timings } = await E.buildTransfer({ username: S.user, privPem: S.privPem, recipient: rcps.find(r => r.username === sel.value), data, filename: f.name, mime: f.type });
        const fd = new FormData(); Object.entries(fields).forEach(([k, v]) => fd.append(k, v)); fd.append('ciphertext', new Blob([blob]), 'evidence.bin');
        const t0 = performance.now();
        const r = await api('/api/transfers', { method: 'POST', body: fd }).then(r => r.json());
        const uploadMs = performance.now() - t0;
        note(out, 'Sent. Transfer ' + r.id + ' (ciphertext SHA-256 ' + r.ciphertext_sha256.slice(0, 16) + '…)', 'ok'); file.value = '';
        reportBox.replaceChildren(window.EVAnalysis.encryptionReport(ctx, { filename: f.name, plain: data, blob, fields, timings, uploadMs, server: r.server_ms, sha: r.ciphertext_sha256 }));
        jpost('/api/metrics', Object.assign({ transfer_id: r.id, kind: 'send', transfer_ms: uploadMs }, timings)).catch(() => {});   // informational only
        loadSent();
      } catch (e) { note(out, e.message, 'bad'); } finally { btn.disabled = false; }
    } }, 'Encrypt & send');
    return el('div', { class: 'stack' }, card('Send evidence', el('label', {}, 'Recipient (investigator)'), sel, el('label', {}, 'Evidence file (any type: text, image, audio, video, document)'), file, btn, out), reportBox);
  }
  const sentBox = el('div');
  async function loadSent() {
    const rows = (await api('/api/sent').then(r => r.json())).transfers;
    sentBox.replaceChildren(table(['To', 'File', 'Type', 'Size', 'Sent', 'Downloaded'], rows.map(t => [t.recipient, t.filename, t.category, size(t.size_bytes), fmt(t.created_at), fmt(t.downloaded_at)])));
  }
  const table = (head, rows, cls) => el('table', cls ? { class: cls } : {}, el('tr', {}, head.map(h => el('th', {}, h))), rows.map(r => el('tr', {}, r.map(c => el('td', {}, c)))));

  // ---- investigator: inbox ----
  const inboxBox = el('div'), resultBox = el('div');
  async function loadInbox() {
    const rows = (await api('/api/inbox').then(r => r.json())).transfers;
    if (!rows.length) return inboxBox.replaceChildren(el('p', { class: 'muted' }, 'No evidence has been sent to you.'));
    inboxBox.replaceChildren(table(['From', 'File', 'Type', 'Size', 'Received', ''], rows.map(t =>
      [t.sender, t.filename, t.category, size(t.size_bytes), fmt(t.created_at), el('button', { class: 'ghost', onclick: () => openTransfer(t) }, 'Download & decrypt')])));
  }
  async function openTransfer(t) {
    if (!S.privPem) return note(resultBox, 'Load your private key first.', 'bad');
    note(resultBox, 'Downloading and verifying…');
    try {
      const d0 = performance.now();
      const meta = await api('/api/transfers/' + t.id).then(r => r.json());
      const blob = new Uint8Array(await api('/api/transfers/' + t.id + '/ciphertext').then(r => r.arrayBuffer()));
      const downloadMs = performance.now() - d0;
      const { plain, report } = await E.openEnvelope(meta, blob, S.privPem);
      report.timings.transfer_ms = downloadMs;
      jpost('/api/metrics', Object.assign({ transfer_id: t.id, kind: 'receive' }, report.timings)).catch(() => {});   // informational only
      const url = URL.createObjectURL(new Blob([plain], { type: t.mime_type }));
      let preview = el('div');
      if (t.category === 'image') preview = el('img', { src: url, alt: t.filename });
      else if (t.category === 'audio') preview = el('audio', { src: url, controls: '' });
      else if (t.category === 'video') preview = el('video', { src: url, controls: '' });
      else if (t.category === 'text') preview = el('pre', {}, new TextDecoder().decode(plain.subarray(0, 20000)));
      resultBox.replaceChildren(cardX('verified', 'Verified: ' + t.filename,
        el('div', {}, el('span', { class: 'ok' }, '✔ sender signature valid  ✔ MAC valid  ✔ decrypted locally')),
        el('p', { class: 'muted' }, 'Sender key fingerprint (confirm out-of-band): '), el('div', { class: 'mono' }, report.senderKeyFp),
        el('p', { class: 'muted' }, 'Plaintext SHA-256:'), el('div', { class: 'mono' }, report.plaintextSha256),
        el('div', { class: 'preview' }, preview),
        el('a', { class: 'save', href: url, download: t.filename.replace(/[\\/\u0000-\u001f]/g, '_') }, el('button', {}, 'Save file')),
        ...window.EVAnalysis.decryptionSection(ctx, { timings: report.timings, blob, plain, meta })));
      loadInbox();
    } catch (e) { note(resultBox, 'FAILED: ' + e.message, 'bad'); }
  }

  // ---- admin ----
  async function adminPanel() {
    const out = el('div'), box = el('div');
    const verify = el('button', { onclick: async () => { const r = await api('/api/audit/verify').then(r => r.json());
      note(out, r.ok ? `Audit chain intact (${r.entries} entries).` : `CHAIN BROKEN at entry #${r.first_bad_id}`, r.ok ? 'ok' : 'bad'); } }, 'Verify audit chain');
    const rows = (await api('/api/audit?limit=100').then(r => r.json())).entries;
    box.append(table(['#', 'Time (UTC)', 'Actor', 'Action', 'Target', 'Detail'], rows.map(r => [r.id, r.ts, r.actor, r.action, r.target, r.detail])));
    return card('Audit log (chain of custody)', verify, out, box);
  }

  // ---- views ----
  function loginView() {
    const u = el('input', { type: 'text', autocomplete: 'username' }), p = el('input', { type: 'password', autocomplete: 'current-password' }), out = el('div');
    const go = async () => { try { const d = await jpost('/api/login', { username: u.value, password: p.value });
      S.token = d.token; S.user = d.username; S.role = d.role; sessionStorage.setItem('ev_token', d.token); sessionStorage.setItem('ev_user', d.username); sessionStorage.setItem('ev_role', d.role); render(); }
      catch (e) { note(out, e.message, 'bad'); } };
    p.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    app.replaceChildren(el('div', { class: 'card' }, el('h2', {}, 'Sign in'), el('label', {}, 'Username'), u, el('label', {}, 'Password'), p, el('button', { onclick: go }, 'Sign in'), out));
  }

  // ---- tabs: the work screen for this role, and the analysis screen ----
  const tabs = document.getElementById('tabs');
  const WORK = { officer: 'Send evidence', investigator: 'Inbox', admin: 'Audit log' };
  function drawTabs() {
    tabs.replaceChildren();
    if (!S.token) return;
    [['work', WORK[S.role] || 'Work'], ['analysis', 'Analysis']].forEach(([id, label]) => tabs.append(el('button', {
      class: 'tab', 'aria-current': S.view === id ? 'page' : null, onclick: () => { S.view = id; sessionStorage.setItem('ev_view', id); render(); } }, label)));
  }

  async function render() {
    who.replaceChildren();
    if (!S.token) { tabs.replaceChildren(); return loginView(); }
    who.append(el('span', { class: 'muted' }, `${S.user} (${S.role}) `), el('button', { class: 'ghost', onclick: logout }, 'Sign out'));
    S.view = S.view || sessionStorage.getItem('ev_view') || 'work';
    drawTabs();
    app.replaceChildren();
    try {
      if (S.view === 'analysis') { app.append(el('p', { class: 'muted loading' }, 'Loading…')); app.replaceChildren(...await window.EVAnalysis.build(ctx)); return; }
      if (S.role !== 'admin') app.append(keyPanel());
      if (S.role === 'officer') { app.append(await sendPanel(), card('Sent evidence', sentBox)); loadSent(); }
      if (S.role === 'investigator') { app.append(card('Inbox', inboxBox), resultBox); loadInbox(); }
      if (S.role === 'admin') app.append(await adminPanel());
    } catch (e) { app.append(el('div', { class: 'msg bad' }, e.message)); }
  }
  const ctx = { el, card, table, api, size, fmt, S };
  render();
})();
