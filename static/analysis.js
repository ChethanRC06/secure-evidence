/* Timing reports, ciphertext display, charts, security analysis and packet-capture views.
   Loaded before app.js; app.js passes its helpers in as `ctx` ({ el, card, table, api, size, fmt, S }).
   Everything that comes from the server is inserted with textContent (el()), never as HTML.
   Charts are plain SVG styled by CSS classes, because the page's Content-Security-Policy forbids inline styles. */
(function () {
  'use strict';
  const E = window.EVCrypto, NS = 'http://www.w3.org/2000/svg';
  const now = () => performance.now();

  // ------------------------------------------------------------------ formatting
  function fmtMs(v) {
    if (v == null || Number.isNaN(v)) return '—';
    if (v === 0) return '< 0.1 ms';                       // below the browser's timer resolution
    if (v >= 100) return v.toFixed(0) + ' ms';
    if (v >= 10) return v.toFixed(1) + ' ms';
    if (v >= 1) return v.toFixed(2) + ' ms';
    if (v >= 0.001) return v.toFixed(3) + ' ms';
    return '< 0.001 ms';
  }
  function sizeLabel(n) {
    if (n >= 1048576) return +(n / 1048576).toFixed(2) + ' MB';
    if (n >= 1024) return +(n / 1024).toFixed(1) + ' KB';
    return n + ' B';
  }
  const tickNum = (v) => (v === 0 ? '0' : String(+v.toPrecision(3)));
  const median = (a) => { const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
  const mbps = (bytes, ms) => (ms > 0 ? (bytes / 1048576) / (ms / 1000) : null);
  const when = (iso) => { try { return new Date(iso).toLocaleString(); } catch (e) { return iso || ''; } };

  // ------------------------------------------------------------------ tiny SVG helper
  function svg(tag, attrs, ...kids) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    kids.flat().forEach(c => n.append(c instanceof Node ? c : document.createTextNode(c ?? '')));
    return n;
  }

  // ------------------------------------------------------------------ hex dump and ciphertext display
  function hexdump(u8, count, start) {
    start = start || 0;
    const lines = [], end = Math.min(count, u8.length);
    for (let i = 0; i < end; i += 16) {
      const row = u8.subarray(i, Math.min(i + 16, end));
      const hex = Array.from(row, b => b.toString(16).padStart(2, '0'));
      const left = hex.slice(0, 8).join(' '), right = hex.slice(8).join(' ');
      const ascii = Array.from(row, b => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
      lines.push((start + i).toString(16).padStart(6, '0') + '  ' + (left + '  ' + right).padEnd(49) + ' |' + ascii + '|');
    }
    return lines.join('\n');
  }
  const toHex = (u8, n) => Array.from(u8.subarray(0, n), b => b.toString(16).padStart(2, '0')).join('');

  /* What the server (and anyone on the network) holds: the encrypted envelope, side by side with the plaintext. */
  function ciphertextView(ctx, o) {
    const { el } = ctx, blob = o.blob, plain = o.plain, n = blob.length;
    const SHOW = [96, 512, 2048];
    const plainPre = el('pre', { class: 'hex', tabindex: '0', 'aria-label': 'Plaintext hex dump' });
    const cipherPre = el('pre', { class: 'hex', tabindex: '0', 'aria-label': 'Ciphertext hex dump' });
    const tailPre = el('pre', { class: 'hex', tabindex: '0', 'aria-label': 'End of the ciphertext' }, hexdump(blob.subarray(Math.max(0, n - 48)), 48, Math.max(0, n - 48)));
    const sel = el('select', { 'aria-label': 'Bytes to show' }, SHOW.map(v => el('option', { value: v }, v + ' bytes')));
    const fill = () => { const c = +sel.value; plainPre.textContent = hexdump(plain, c); cipherPre.textContent = hexdump(blob, c); };
    sel.addEventListener('change', fill); fill();

    const seg = (cls, name, bytes) => el('span', { class: 'seg ' + cls }, el('b', {}, name), ' ' + sizeLabel(bytes));
    const copy = el('button', { class: 'ghost', onclick: async () => {
      try { await navigator.clipboard.writeText(toHex(blob, 4096)); copy.textContent = 'Copied first 4 KB'; } catch (e) { copy.textContent = 'Copy not allowed here'; }
    } }, 'Copy first 4 KB as hex');
    const save = el('button', { class: 'ghost', onclick: () => {
      const url = URL.createObjectURL(new Blob([blob], { type: 'application/octet-stream' }));
      const a = document.createElement('a'); a.href = url; a.download = (o.filename || 'evidence') + '.enc'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 4000);
    } }, 'Save ciphertext (.enc)');
    const full = (label, text) => el('details', { class: 'inner' }, el('summary', {}, label), el('div', { class: 'mono' }, text));

    return el('details', { class: 'ctview', open: '' },
      el('summary', {}, o.heading || 'Ciphertext'),
      el('p', { class: 'muted' }, o.intro || 'This is exactly what is stored on the server and what anyone on the network could copy. Without the recipient’s private key it cannot be read.'),
      el('div', { class: 'segs', role: 'img', 'aria-label': 'Envelope layout' },
        seg('s-magic', 'EVC1', 4), seg('s-iv', 'IV', 16), seg('s-ct', 'AES-256-CBC ciphertext', Math.max(0, n - 52)), seg('s-tag', 'HMAC-SHA256 tag', 32)),
      el('div', { class: 'row' }, el('label', { class: 'inline' }, 'Show first '), sel),
      el('div', { class: 'hexpair' },
        el('div', {}, el('div', { class: 'hexhead' }, o.plainLabel || 'Plaintext (before encryption)'), plainPre),
        el('div', {}, el('div', { class: 'hexhead' }, 'Ciphertext (what is sent and stored)'), cipherPre)),
      el('details', { class: 'inner' }, el('summary', {}, 'Last 48 bytes (the final 32 are the integrity tag)'), tailPre),
      el('dl', { class: 'facts' },
        el('dt', {}, 'Plaintext'), el('dd', {}, sizeLabel(plain.length) + ' (' + plain.length.toLocaleString() + ' bytes)'),
        el('dt', {}, 'Ciphertext'), el('dd', {}, sizeLabel(n) + ' (' + n.toLocaleString() + ' bytes), ' + (n - plain.length) + ' bytes larger: header, IV, padding and tag'),
        o.sha ? [el('dt', {}, 'Ciphertext SHA-256'), el('dd', { class: 'mono' }, o.sha)] : []),
      o.wrappedKey ? full('Encrypted file key (RSA-OAEP wrapped for the recipient, base64)', o.wrappedKey) : null,
      o.signature ? full('Sender’s signature (RSA-PSS, base64)', o.signature) : null,
      el('div', { class: 'row actions' }, save, copy));
  }

  // ------------------------------------------------------------------ timing table
  function timingTable(ctx, rows, caption) {
    const { el } = ctx;
    const crypto = rows.filter(r => !r.nobar && !r.total && r.ms != null).map(r => r.ms);
    const max = Math.max(...crypto, 0.0001);
    const t = el('table', { class: 'timing' }, el('caption', {}, caption),
      el('tr', {}, ['Step', 'Time', ''].map((h, i) => el('th', i === 1 ? { class: 'r' } : {}, h))),
      rows.map(r => {
        const bar = el('div', { class: 'bar' }, el('span', {}));
        if (!r.nobar && !r.total && r.ms != null) bar.firstChild.style.width = Math.max(2, (r.ms / max) * 100) + '%';
        else bar.classList.add('none');
        return el('tr', { class: (r.key ? 'key ' : '') + (r.total ? 'total' : '') },
          el('td', {}, el('div', { class: 'tl' }, r.label), r.detail ? el('div', { class: 'muted small' }, r.detail) : null),
          el('td', { class: 'r' }, fmtMs(r.ms)), el('td', { class: 'barcell' }, bar));
      }));
    return t;
  }

  /* The requested numbers, at a glance: first item is the headline. items = [[label, ms], ...] */
  function stats(ctx, items) {
    const { el } = ctx;
    return el('dl', { class: 'stats' }, items.map(([k, ms], i) => el('div', { class: i === 0 ? 'lead' : '' }, el('dt', {}, k), el('dd', {}, fmtMs(ms)))));
  }

  /* Sender: shown after "Encrypt & send". d = { filename, plain, blob, fields, timings, uploadMs, server, id } */
  function encryptionReport(ctx, d) {
    const { el } = ctx, t = d.timings || {};
    const rows = [
      { label: 'Encryption', detail: 'AES-256-CBC + HMAC-SHA256 · AES ' + fmtMs(t.aes_ms) + ' + HMAC ' + fmtMs(t.mac_ms), ms: t.encrypt_ms, key: true },
      { label: 'Key wrapping', detail: 'RSA-OAEP-2048, for the recipient', ms: t.wrap_ms },
      { label: 'Hashing', detail: 'SHA-256 of the ciphertext and the wrapped key', ms: t.hash_ms },
      { label: 'Signature generation', detail: 'RSA-PSS-2048 with your private key', ms: t.sign_ms, key: true },
      { label: 'Total on this device', ms: t.total_ms, total: true },
      { label: 'Upload', detail: 'network round trip, including the checks below', ms: d.uploadMs, nobar: true },
      { label: 'Signature verification by the server', detail: 'done before anything is stored', ms: d.server && d.server.verify_ms, nobar: true, key: true }];
    return el('div', { class: 'card report' }, el('h2', {}, 'Encryption report: ' + d.filename),
      el('p', { class: 'muted' }, 'Everything below ran in your browser before the file left your computer. Browsers round timers to about 0.1 ms, so very small values are approximate.'),
      stats(ctx, [['Encryption time', t.encrypt_ms], ['Signature generation', t.sign_ms], ['Total on this device', t.total_ms]]),
      timingTable(ctx, rows, 'Sender timings'),
      ciphertextView(ctx, { plain: d.plain, blob: d.blob, filename: d.filename, sha: d.sha, wrappedKey: d.fields.wrapped_key, signature: d.fields.signature,
        heading: 'Ciphertext that was sent' }));
  }

  /* Receiver: rows and ciphertext view for the "Verified" card. d = { timings, blob, plain, meta } */
  function decryptionSection(ctx, d) {
    const { el } = ctx, t = d.timings || {};
    const rows = [
      { label: 'Download', detail: 'metadata and ciphertext from the server', ms: t.transfer_ms, nobar: true },
      { label: 'Ciphertext hash check', detail: 'SHA-256 compared with the server’s record · key checks ' + fmtMs(t.check_ms), ms: t.hash_ms },
      { label: 'Signature verification', detail: 'RSA-PSS-2048 with the sender’s public key', ms: t.verify_ms, key: true },
      { label: 'Key unwrapping', detail: 'RSA-OAEP-2048 with your private key', ms: t.unwrap_ms },
      { label: 'MAC check', detail: 'HMAC-SHA256, before any decryption', ms: t.mac_ms },
      { label: 'AES decryption', detail: 'AES-256-CBC', ms: t.aes_ms },
      { label: 'Decryption', detail: 'MAC check + AES-256-CBC', ms: t.decrypt_ms, key: true },
      { label: 'Total on this device', detail: 'verify + unwrap + decrypt', ms: t.total_ms, total: true }];
    return [el('h3', {}, 'Decryption report'),
      stats(ctx, [['Decryption time', t.decrypt_ms], ['Signature verification', t.verify_ms], ['Total on this device', t.total_ms]]),
      timingTable(ctx, rows, 'Receiver timings'),
      ciphertextView(ctx, { plain: d.plain, blob: d.blob, filename: d.meta.filename, sha: d.meta.ciphertext_sha256, wrappedKey: d.meta.wrapped_key,
        signature: d.meta.signature, heading: 'Ciphertext as downloaded', plainLabel: 'Plaintext (after decryption)',
        intro: 'This is the file as it was stored on the server. Your private key turned it back into the plaintext on the right.' })];
  }

  // ------------------------------------------------------------------ benchmarks (run in this browser)
  function randomBytes(n) {
    const u = new Uint8Array(n);
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(u.subarray(i, Math.min(i + 65536, n)));
    return u;
  }
  const frame = () => new Promise(r => setTimeout(r, 0));

  /* Median of several samples; each sample loops the call until it lasts >= 25 ms so timer rounding does not matter. */
  async function measure(fn, bytes) {
    await fn();                                               // warm-up (JIT, key import caches)
    let n = 1;
    for (;;) {
      const t = now(); for (let i = 0; i < n; i++) await fn();
      const el = now() - t;
      if (el >= 25 || n >= 4096) break;
      n = Math.min(4096, Math.max(n * 2, Math.ceil(n * 25 / Math.max(el, 0.01))));
    }
    const samples = [], reps = bytes >= (4 << 20) ? 5 : 9;
    for (let r = 0; r < reps; r++) { const t = now(); for (let i = 0; i < n; i++) await fn(); samples.push((now() - t) / n); }
    return median(samples);
  }
  const SIZES = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20];

  async function benchSizes(progress) {
    const out = [];
    for (let i = 0; i < SIZES.length; i++) {
      const n = SIZES[i]; progress('Measuring ' + sizeLabel(n) + ' (' + (i + 1) + ' of ' + SIZES.length + ')…');
      const data = randomBytes(n), enc = await measure(() => E.encrypt(data), n), one = await E.encrypt(data);
      const dec = await measure(() => E.decrypt(one.blob, one.keymat), n);
      out.push({ bytes: n, enc_ms: enc, dec_ms: dec }); await frame();
    }
    return out;
  }
  async function benchPublicKey(progress) {
    progress('Generating a 2048-bit RSA key…');
    const kp = await E.generateKeyPem(), msg = new TextEncoder().encode('benchmark message '.repeat(20)), key = new Uint8Array(64).fill(7);
    const sig = await E.sign(kp.priv, msg), wrapped = await E.wrapKey(kp.pub, key), r = {};
    progress('Measuring signature generation…'); r.sign = await measure(() => E.sign(kp.priv, msg), 0);
    progress('Measuring signature verification…'); r.verify = await measure(() => E.verify(kp.pub, msg, sig), 0);
    progress('Measuring key wrapping…'); r.wrap = await measure(() => E.wrapKey(kp.pub, key), 0);
    progress('Measuring key unwrapping…'); r.unwrap = await measure(() => E.unwrapKey(kp.priv, wrapped), 0);
    return r;
  }

  // ------------------------------------------------------------------ chart helpers
  const tipFor = (ctx, box) => {
    const tip = ctx.el('div', { class: 'tip', role: 'status', 'aria-live': 'polite' }); tip.hidden = true; box.append(tip); return tip;
  };
  function placeTip(tip, box, px, py) {
    tip.hidden = false;
    const bw = box.clientWidth, tw = tip.offsetWidth;
    tip.style.left = Math.max(4, Math.min(px + 14, bw - tw - 4)) + 'px';
    tip.style.top = Math.max(4, py) + 'px';
  }
  function legend(ctx, items) {
    const { el } = ctx;
    return el('ul', { class: 'legend', 'aria-label': 'Chart legend' }, items.map(i => el('li', {},
      svg('svg', { width: 26, height: 10, 'aria-hidden': 'true' }, svg('line', { x1: 1, y1: 5, x2: 25, y2: 5, class: 'ln ' + i.cls + (i.dash ? ' dash' : '') })), i.label)));
  }

  /* Line chart: x = plaintext length, y = time. series: [{ id, label, cls, dash, direct, pts: [[x, y], ...] }] */
  function lineChart(ctx, o) {
    const { el } = ctx;
    const series = o.series.filter(s => s.pts.length), W = 760, H = 380, m = { l: 66, r: 112, t: 16, b: 54 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b, log = o.mode === 'log';
    const box = el('div', { class: 'chartbox' });
    if (!series.length) { box.append(el('p', { class: 'muted empty' }, 'No data yet. Press “Measure in this browser”.')); return box; }
    const xsAll = [...new Set(series.flatMap(s => s.pts.map(p => p[0])))].sort((a, b) => a - b);
    const ysAll = series.flatMap(s => s.pts.map(p => p[1])).filter(v => v > 0);
    const xmin = xsAll[0], xmax = xsAll[xsAll.length - 1], ymin = Math.min(...ysAll), ymax = Math.max(...ysAll);
    const ylo = log ? Math.pow(10, Math.floor(Math.log10(ymin))) : 0;
    const niceTop = (v) => { const p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; };
    let yhi = log ? Math.pow(10, Math.ceil(Math.log10(ymax))) : niceTop(ymax);
    if (log && yhi <= ylo) yhi = ylo * 10;
    const sx = (x) => log ? m.l + (xsAll.length < 2 ? 0.5 : (Math.log(x) - Math.log(xmin)) / (Math.log(xmax) - Math.log(xmin))) * iw : m.l + (x / xmax) * iw;
    const sy = (y) => log ? m.t + ih - (Math.log(Math.max(y, ylo)) - Math.log(ylo)) / (Math.log(yhi) - Math.log(ylo)) * ih : m.t + ih - (y / yhi) * ih;

    const g = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'chart', role: 'img', tabindex: '0',
      'aria-label': o.title + '. Use the arrow keys to read each point; the same numbers are in the table below.' });
    // grid + y axis
    const yt = [];
    if (log) { for (let v = ylo; v <= yhi * 1.0001; v *= 10) yt.push(v); } else { for (let i = 0; i <= 4; i++) yt.push(yhi * i / 4); }
    yt.forEach(v => {
      g.append(svg('line', { x1: m.l, x2: W - m.r, y1: sy(v), y2: sy(v), class: 'grid' }),
        svg('text', { x: m.l - 8, y: sy(v) + 4, class: 'tick', 'text-anchor': 'end' }, tickNum(v)));
    });
    g.append(svg('text', { x: 14, y: m.t + ih / 2, class: 'axlabel', transform: 'rotate(-90 14 ' + (m.t + ih / 2) + ')', 'text-anchor': 'middle' }, 'Time (ms)' + (log ? ', log scale' : '')));
    // x axis
    const xt = log ? xsAll : [0, 1, 2, 3, 4].map(i => xmax * i / 4);
    xt.forEach(v => g.append(svg('line', { x1: sx(v), x2: sx(v), y1: m.t + ih, y2: m.t + ih + 4, class: 'axis' }),
      svg('text', { x: sx(v), y: m.t + ih + 18, class: 'tick', 'text-anchor': 'middle' }, v === 0 ? '0' : sizeLabel(Math.round(v)))));
    g.append(svg('line', { x1: m.l, x2: W - m.r, y1: m.t + ih, y2: m.t + ih, class: 'axis' }),
      svg('text', { x: m.l + iw / 2, y: H - 10, class: 'axlabel', 'text-anchor': 'middle' }, 'Plaintext length' + (log ? ' (log scale)' : '')));
    // lines, dots, direct labels
    const labelY = [];
    series.forEach(s => {
      g.append(svg('polyline', { points: s.pts.map(p => sx(p[0]) + ',' + sy(p[1])).join(' '), class: 'ln ' + s.cls + (s.dash ? ' dash' : ''), fill: 'none' }));
      s.pts.forEach(p => g.append(svg('circle', { cx: sx(p[0]), cy: sy(p[1]), r: 4, class: 'dot ' + s.cls })));
      const last = s.pts[s.pts.length - 1], y = sy(last[1]);
      if (s.direct && labelY.every(v => Math.abs(v - y) >= 16)) {      // only when it will not collide with another label
        labelY.push(y);
        g.append(svg('line', { x1: sx(last[0]) + 8, x2: sx(last[0]) + 20, y1: y, y2: y, class: 'ln ' + s.cls }),
          svg('text', { x: sx(last[0]) + 25, y: y + 4, class: 'dlabel' }, s.short || s.label));
      }
    });
    // hover layer: crosshair snaps to the nearest plaintext length and one tooltip lists every series there
    const cross = svg('line', { y1: m.t, y2: m.t + ih, class: 'cross' }); cross.style.display = 'none'; g.append(cross);
    const tip = tipFor(ctx, box); let cur = -1;
    const show = (idx) => {
      cur = idx; const x = xsAll[idx], px = sx(x);
      cross.setAttribute('x1', px); cross.setAttribute('x2', px); cross.style.display = '';
      tip.replaceChildren(el('div', { class: 'thead' }, sizeLabel(x) + ' plaintext'), series.map(s => {
        const p = s.pts.find(q => q[0] === x);
        return el('div', { class: 'trow' }, svg('svg', { width: 18, height: 8, 'aria-hidden': 'true' }, svg('line', { x1: 1, y1: 4, x2: 17, y2: 4, class: 'ln ' + s.cls + (s.dash ? ' dash' : '') })),
          el('strong', {}, p ? fmtMs(p[1]) : '—'), el('span', { class: 'muted' }, ' ' + s.label));
      }));
      const r = g.getBoundingClientRect(), k = r.width / W;
      placeTip(tip, box, px * k, m.t * k + 6);
    };
    const hide = () => { cross.style.display = 'none'; tip.hidden = true; cur = -1; };
    g.addEventListener('pointermove', (e) => {
      const r = g.getBoundingClientRect(), x = (e.clientX - r.left) / (r.width / W);
      if (x < m.l - 10 || x > W - m.r + 10) return hide();
      let best = 0; xsAll.forEach((v, i) => { if (Math.abs(sx(v) - x) < Math.abs(sx(xsAll[best]) - x)) best = i; });
      show(best);
    });
    g.addEventListener('pointerleave', hide);
    g.addEventListener('blur', hide);
    g.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight') { show(Math.min(xsAll.length - 1, cur + 1)); e.preventDefault(); }
      else if (e.key === 'ArrowLeft') { show(Math.max(0, cur < 0 ? 0 : cur - 1)); e.preventDefault(); }
      else if (e.key === 'Escape') hide();
    });
    box.prepend(g);
    return box;
  }

  /* Horizontal grouped bars for the public-key operations. rows: [{ label, vals: [{ cls, label, v }] }] */
  function barChart(ctx, o) {
    const { el } = ctx, W = 760, m = { l: 262, r: 96, t: 8, b: 40 }, bh = 16, gap = 2, gh = 26;
    const nS = Math.max(...o.rows.map(r => r.vals.length)), grp = nS * bh + (nS - 1) * gap, rowH = grp + gh, H = m.t + o.rows.length * rowH + m.b;
    const max = Math.max(...o.rows.flatMap(r => r.vals.map(v => v.v)), 0.001), top = (() => { const p = Math.pow(10, Math.floor(Math.log10(max))), f = max / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; })();
    const iw = W - m.l - m.r, sx = (v) => m.l + (v / top) * iw, box = el('div', { class: 'chartbox' });
    const g = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'chart', role: 'img', 'aria-label': o.title + '. The same numbers are in the table below.' });
    for (let i = 0; i <= 4; i++) {
      const v = top * i / 4; g.append(svg('line', { x1: sx(v), x2: sx(v), y1: m.t, y2: H - m.b, class: 'grid' }),
        svg('text', { x: sx(v), y: H - m.b + 16, class: 'tick', 'text-anchor': 'middle' }, +v.toPrecision(2)));
    }
    g.append(svg('text', { x: m.l + iw / 2, y: H - 8, class: 'axlabel', 'text-anchor': 'middle' }, 'Time per operation (ms)'));
    const tip = tipFor(ctx, box);
    o.rows.forEach((r, ri) => {
      const y0 = m.t + ri * rowH + gh / 2;
      g.append(svg('text', { x: m.l - 12, y: y0 + grp / 2 + 4, class: 'catlabel', 'text-anchor': 'end' }, r.label));
      r.vals.forEach((v, vi) => {
        const y = y0 + vi * (bh + gap), w = Math.max(2, sx(v.v) - m.l), rr = Math.min(4, w / 2);
        const d = 'M' + m.l + ',' + y + ' h' + (w - rr) + ' a' + rr + ',' + rr + ' 0 0 1 ' + rr + ',' + rr + ' v' + (bh - 2 * rr) + ' a' + rr + ',' + rr + ' 0 0 1 -' + rr + ',' + rr + ' h-' + (w - rr) + ' z';
        const bar = svg('path', { d, class: 'bar-mark ' + v.cls, tabindex: '0', role: 'img', 'aria-label': r.label + ', ' + v.label + ': ' + fmtMs(v.v) });
        const on = (e) => {
          tip.replaceChildren(el('div', { class: 'thead' }, r.label), el('div', { class: 'trow' }, svg('svg', { width: 18, height: 8, 'aria-hidden': 'true' }, svg('line', { x1: 1, y1: 4, x2: 17, y2: 4, class: 'ln ' + v.cls })),
            el('strong', {}, fmtMs(v.v)), el('span', { class: 'muted' }, ' ' + v.label)));
          const rc = g.getBoundingClientRect(), k = rc.width / W; placeTip(tip, box, (sx(v.v) + 6) * k, (y - 4) * k);
        };
        bar.addEventListener('pointermove', on); bar.addEventListener('focus', on);
        bar.addEventListener('pointerleave', () => { tip.hidden = true; }); bar.addEventListener('blur', () => { tip.hidden = true; });
        g.append(bar, svg('text', { x: sx(v.v) + 8, y: y + bh - 4, class: 'vlabel' }, fmtMs(v.v)));
      });
    });
    g.append(svg('line', { x1: m.l, x2: m.l, y1: m.t, y2: H - m.b, class: 'axis' }));
    box.prepend(g); return box;
  }

  // ------------------------------------------------------------------ analysis page sections
  const pill = (ctx, ok, yes, no) => ctx.el('span', { class: 'pill ' + (ok ? 'good' : 'bad') }, (ok ? '✔ ' : '✖ ') + (ok ? yes : no));
  const noReport = (ctx, cmd) => ctx.el('p', { class: 'muted' }, 'No report has been generated yet. Run  ', ctx.el('code', {}, cmd), '  on the server computer and reload this page.');

  async function getReport(ctx, name) {
    try { const r = await ctx.api('/api/reports/' + name).then(x => x.json()); return r.available ? r : null; } catch (e) { return null; }
  }

  // ---- 1. measurements of real transfers
  async function measurementsCard(ctx) {
    const { el, table } = ctx; let rows = [];
    try { rows = (await ctx.api('/api/metrics?limit=100').then(r => r.json())).metrics; } catch (e) { /* shown as empty */ }
    const kind = { send: 'Sent', receive: 'Received', server: 'Server check' };
    const body = rows.length ? el('div', { class: 'tablewrap' }, table(['When', 'File', ...(ctx.S.role === 'admin' ? ['User'] : []), 'Event', 'Size', 'Encryption', 'Decryption', 'Signature generation', 'Signature verification', 'Total'],
      rows.map(r => [ctx.fmt(r.created_at), r.filename, ...(ctx.S.role === 'admin' ? [r.username] : []), kind[r.kind] || r.kind, sizeLabel(r.plaintext_bytes),
        r.kind === 'send' ? fmtMs(r.encrypt_ms) : '—', r.kind === 'receive' ? fmtMs(r.decrypt_ms) : '—', r.kind === 'send' ? fmtMs(r.sign_ms) : '—',
        r.kind === 'receive' || r.kind === 'server' ? fmtMs(r.verify_ms) : '—', r.kind === 'server' ? '—' : fmtMs(r.total_ms)]), 'num'))
      : el('p', { class: 'muted' }, 'Nothing recorded yet. Send or receive a file and its encryption, decryption and signature times will be listed here.');
    return el('div', { class: 'card' }, el('h2', {}, 'Times from your real transfers'),
      el('p', { class: 'muted' }, ctx.S.role === 'admin' ? 'All users’ measurements.' : 'Your own transfers. “Server check” is the server verifying the sender’s signature at upload.'), body);
  }

  // ---- 2. encryption time vs plaintext length (chart)
  async function sizeChartCard(ctx, bench) {
    const { el } = ctx;
    const st = { browser: [], showDec: false, mode: 'log' };
    const py = bench && bench.report ? bench.report : null;
    const pyRows = py ? py.sizes_bytes.map((b, i) => ({ bytes: b, enc_ms: py.series.encrypt_ms[i], dec_ms: py.series.decrypt_ms[i] })) : [];
    const chartBox = el('div'), tableBox = el('div'), status = el('div', { class: 'muted small', role: 'status', 'aria-live': 'polite' }), insight = el('p', { class: 'insight' });

    const draw = () => {
      const series = [
        { cls: 's-browser', label: 'Encryption, this browser', short: 'Browser', direct: true, pts: st.browser.map(r => [r.bytes, r.enc_ms]) },
        { cls: 's-python', label: 'Encryption, server Python (OpenSSL)', short: 'Python', direct: true, pts: pyRows.map(r => [r.bytes, r.enc_ms]) }];
      if (st.showDec) series.push(
        { cls: 's-browser', dash: true, label: 'Decryption, this browser', pts: st.browser.map(r => [r.bytes, r.dec_ms]) },
        { cls: 's-python', dash: true, label: 'Decryption, server Python (OpenSSL)', pts: pyRows.map(r => [r.bytes, r.dec_ms]) });
      const live = series.filter(s => s.pts.length);
      chartBox.replaceChildren(live.length ? legend(ctx, live) : '', lineChart(ctx, { series, mode: st.mode, title: 'Encryption time against plaintext length' }));
      const sizes = [...new Set([...st.browser.map(r => r.bytes), ...pyRows.map(r => r.bytes)])].sort((a, b) => a - b);
      const find = (arr, b) => arr.find(r => r.bytes === b);
      tableBox.replaceChildren(sizes.length ? el('div', { class: 'tablewrap' }, ctx.table(
        ['Plaintext length', 'Encryption (browser)', 'Decryption (browser)', 'Browser speed', 'Encryption (Python)', 'Decryption (Python)'],
        sizes.map(b => { const a = find(st.browser, b), p = find(pyRows, b), sp = a && mbps(b, a.enc_ms);
          return [sizeLabel(b), a ? fmtMs(a.enc_ms) : '—', a ? fmtMs(a.dec_ms) : '—', sp ? sp.toFixed(0) + ' MB/s' : '—', p ? fmtMs(p.enc_ms) : '—', p ? fmtMs(p.dec_ms) : '—']; }), 'num')) : '');
      // plain-language reading of the result: slope of log(time) against log(size) for the larger files
      const big = st.browser.filter(r => r.bytes >= 65536 && r.enc_ms > 0);
      if (big.length >= 3) {
        const xs = big.map(r => Math.log(r.bytes)), ys = big.map(r => Math.log(r.enc_ms)), mx = xs.reduce((a, b) => a + b) / xs.length, my = ys.reduce((a, b) => a + b) / ys.length;
        const slope = xs.reduce((a, x, i) => a + (x - mx) * (ys[i] - my), 0) / xs.reduce((a, x) => a + (x - mx) ** 2, 0), first = st.browser[0], last = st.browser[st.browser.length - 1];
        insight.textContent = 'Growth is close to linear for files of 64 KB and up (fitted slope ' + slope.toFixed(2) + ' on log-log axes, where 1.00 means doubling the size doubles the time). ' +
          'Encrypting ' + sizeLabel(first.bytes) + ' took ' + fmtMs(first.enc_ms) + ' and ' + sizeLabel(last.bytes) + ' took ' + fmtMs(last.enc_ms) + '. Below about 64 KB a fixed per-call cost dominates, so the line flattens.';
      } else insight.textContent = '';
    };
    const run = el('button', { onclick: async () => {
      run.disabled = true;
      try { st.browser = await benchSizes((t) => { status.textContent = t; }); status.textContent = 'Done. Each value is the median of repeated measurements in this browser.'; draw(); }
      catch (e) { status.textContent = 'Measurement failed: ' + e.message; } finally { run.disabled = false; }
    } }, 'Measure in this browser');
    const seg = (id, label) => el('button', { class: 'ghost seg-btn', 'aria-pressed': String(st.mode === id), onclick: (ev) => {
      st.mode = id; ev.target.parentNode.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === ev.target))); draw(); } }, label);
    const dec = el('input', { type: 'checkbox', onchange: (e) => { st.showDec = e.target.checked; draw(); } });
    draw();
    return el('div', { class: 'card' }, el('h2', {}, 'Encryption time against plaintext length'),
      el('p', { class: 'muted' }, 'Browser values are measured live on this device with WebCrypto, the same code that encrypts your evidence. The orange line is the server-side Python reference' +
        (py ? ' (' + py.engine + ', generated ' + when(py.generated_at) + ').' : ': not generated yet, run  python scripts/benchmark.py  to add it.')),
      el('div', { class: 'row controls' }, run, el('div', { class: 'segctl', role: 'group', 'aria-label': 'Axis scale' }, seg('log', 'Log axes'), seg('linear', 'Linear axes')),
        el('label', { class: 'check' }, dec, ' Also show decryption')), status, chartBox, insight, tableBox);
  }

  // ---- 3. signature generation / verification time
  async function signatureCard(ctx, bench) {
    const { el } = ctx, py = bench && bench.report ? bench.report.ops : null;
    const st = { browser: null }, box = el('div'), status = el('div', { class: 'muted small', role: 'status', 'aria-live': 'polite' }), tbl = el('div'), insight = el('p', { class: 'insight' });
    const OPS = [['sign', 'rsa2048_sign_ms', 'Signature generation (RSA-PSS sign)'], ['verify', 'rsa2048_verify_ms', 'Signature verification (RSA-PSS verify)'],
      ['wrap', 'rsa_oaep_wrap_ms', 'Key wrapping (RSA-OAEP encrypt)'], ['unwrap', 'rsa_oaep_unwrap_ms', 'Key unwrapping (RSA-OAEP decrypt)']];
    const draw = () => {
      const rows = OPS.map(([k, pk, label]) => ({ label, vals: [
        ...(st.browser ? [{ cls: 's-browser', label: 'This browser', v: st.browser[k] }] : []),
        ...(py && py[pk] ? [{ cls: 's-python', label: 'Server Python (OpenSSL)', v: py[pk].median }] : [])] })).filter(r => r.vals.length);
      if (!rows.length) { box.replaceChildren(el('p', { class: 'muted empty' }, 'No data yet. Press “Measure in this browser”.')); tbl.replaceChildren(); return; }
      const used = [st.browser ? { cls: 's-browser', label: 'This browser' } : null, py ? { cls: 's-python', label: 'Server Python (OpenSSL)' } : null].filter(Boolean);
      box.replaceChildren(legend(ctx, used), barChart(ctx, { rows, title: 'RSA-2048 operation times' }));
      tbl.replaceChildren(el('div', { class: 'tablewrap' }, ctx.table(['Operation', 'This browser', 'Server Python (OpenSSL)'],
        OPS.map(([k, pk, label]) => [label, st.browser ? fmtMs(st.browser[k]) : '—', py && py[pk] ? fmtMs(py[pk].median) : '—']), 'num')));
      const b = st.browser || (py && { sign: py.rsa2048_sign_ms.median, verify: py.rsa2048_verify_ms.median });
      if (b && b.verify > 0) insight.textContent = 'Generating a signature took about ' + (b.sign / b.verify).toFixed(0) + ' times longer than verifying one. Signing uses the 2048-bit private exponent; verifying only uses the short public exponent 65537. That is why a receiver can check signatures cheaply.';
    };
    const run = el('button', { onclick: async () => {
      run.disabled = true;
      try { st.browser = await benchPublicKey((t) => { status.textContent = t; }); status.textContent = 'Done. Each value is the median of repeated measurements, including importing the key as the application does.'; draw(); }
      catch (e) { status.textContent = 'Measurement failed: ' + e.message; } finally { run.disabled = false; }
    } }, 'Measure in this browser');
    draw();
    return el('div', { class: 'card' }, el('h2', {}, 'Signature generation and verification time'),
      el('p', { class: 'muted' }, 'Time for one RSA-2048 operation. These do not depend on the size of the file, because the signature covers a fixed-size message (it includes the SHA-256 hash of the ciphertext).'),
      el('div', { class: 'row controls' }, run), status, box, insight, tbl);
  }

  // ---- 4. security analysis
  function entropy(u8) {
    const c = new Array(256).fill(0); u8.forEach(b => c[b]++); let h = 0;
    c.forEach(v => { if (v) { const p = v / u8.length; h -= p * Math.log2(p); } }); return h;
  }
  const ALGOS = [
    ['File encryption', 'AES-256-CBC', '256-bit key, fresh random key and IV per file', 'Brute force needs about 2^256 tries'],
    ['Integrity and authenticity of the ciphertext', 'HMAC-SHA256 (encrypt-then-MAC)', '256-bit MAC key, checked before decrypting', 'Any change to the IV or ciphertext is rejected'],
    ['Delivering the file key', 'RSA-OAEP, 2048-bit, SHA-256', 'Wrapped for one named recipient', 'About 112-bit security (NIST estimate for RSA-2048)'],
    ['Proving who sent it', 'RSA-PSS, 2048-bit, SHA-256', 'Signs sender, recipient, file details, ciphertext hash, time, nonce', 'About 112-bit security; the receiver checks it'],
    ['Fingerprints and hashes', 'SHA-256', '256-bit output', '128-bit collision resistance']];
  const THREATS = [
    ['Eavesdropper on the network', 'File name, sizes and times over plain HTTP; nothing readable over HTTPS', 'Read the evidence (it is encrypted in the browser before it is sent)', 'Packet capture, scenarios B and C'],
    ['Curious server administrator or database thief', 'Ciphertext, wrapped keys, public keys, metadata', 'Decrypt (no private keys on the server) or change a file without detection', 'Confidentiality and Integrity tests'],
    ['Another investigator', 'Nothing: the server answers 404', 'Even with copied ciphertext, unwrap the key (it is wrapped for someone else)', 'Authorization tests'],
    ['A different officer pretending to be the sender', 'Their own account only', 'Produce a signature that verifies as someone else', 'Authenticity tests'],
    ['Someone who replays an old upload', 'A copy of a past request', 'Get it accepted again (nonce and time window)', 'Replay tests'],
    ['Someone who edits stored evidence or the audit log', 'Write access to storage or the database', 'Do it without detection (hash, MAC and the audit hash chain)', 'Integrity and Audit tests']];
  const LIMITS = [
    'The server hands out public keys. A malicious server could swap in its own key. Compare key fingerprints out of band to rule that out.',
    'File names, types, sizes, recipients and times are visible to the server. Only the file contents are encrypted.',
    'Private keys are loaded from a plain PEM file. Anyone who copies the file can read that user’s evidence.',
    'Over plain HTTP, passwords and session tokens are visible on the network. Use HTTPS in any real deployment.',
    'Timings reported by browsers are informational and are never used for a security decision.'];

  async function securityCard(ctx, rep) {
    const { el } = ctx, tamperBox = el('div'), status = el('div', { class: 'muted small', role: 'status', 'aria-live': 'polite' });
    const run = el('button', { onclick: async () => {
      run.disabled = true; status.textContent = 'Creating a throw-away sender and receiver (two new RSA keys)…'; tamperBox.replaceChildren();
      try {
        const text = new TextEncoder().encode('Witness statement - case 2026/0417. I saw the vehicle at 21:40.\n'.repeat(900));
        const b = await E.selfTestBundle(text);
        await E.openEnvelope(b.meta, b.blob, b.privPem);          // control: the untouched transfer must open
        status.textContent = 'Running ' + 10 + ' attacks…'; const attacks = await E.tamperTest(b.meta, b.blob, b.privPem);
        const caught = attacks.filter(a => a.detected).length, hp = entropy(text), hc = entropy(b.blob);
        tamperBox.replaceChildren(
          el('div', { class: 'msg ' + (caught === attacks.length ? 'ok' : 'bad') }, caught + ' of ' + attacks.length + ' attacks were detected. The untouched control transfer opened correctly.'),
          el('div', { class: 'tablewrap' }, ctx.table(['Attack', 'What should stop it', 'Outcome', 'Reason given'], attacks.map(a => [a.name, a.expect, pill(ctx, a.detected, 'Detected', 'NOT detected'), a.message]), 'tamper')),
          el('p', { class: 'insight' }, 'Randomness check: the plaintext has ' + hp.toFixed(2) + ' bits of entropy per byte, the ciphertext ' + hc.toFixed(3) + ' (the maximum is 8). Good ciphertext is indistinguishable from random bytes.'));
        status.textContent = '';
      } catch (e) { status.textContent = 'Test failed: ' + e.message; } finally { run.disabled = false; }
    } }, 'Run attack tests in this browser');

    let suite = noReport(ctx, 'python scripts/security_analysis.py');
    if (rep) {
      const r = rep.report, s = r.summary;
      suite = el('div', {},
        el('div', { class: 'msg ' + (s.failed === 0 ? 'ok' : 'bad') }, s.passed + ' of ' + s.total + ' attack scenarios were stopped as intended. Run against the real application on ' + when(r.generated_at) + '.'),
        el('div', { class: 'cats' }, Object.entries(s.by_category).map(([cat, v]) => {
          const items = r.scenarios.filter(x => x.category === cat), bar = el('div', { class: 'bar' + (v.passed === v.total ? '' : ' warn') }, el('span', {}));
          bar.firstChild.style.width = (v.total ? v.passed / v.total * 100 : 0) + '%';
          return el('details', { class: 'cat' }, el('summary', {}, el('span', { class: 'catname' }, cat), el('span', { class: 'catn' }, v.passed + ' / ' + v.total), bar),
            el('ul', { class: 'scen' }, items.map(x => el('li', {}, pill(ctx, x.passed, 'Passed', 'Failed'), ' ', el('strong', {}, x.title),
              el('div', { class: 'muted small' }, 'Expected: ' + x.expected), el('div', { class: 'muted small' }, 'Observed: ' + x.observed)))));
        })));
    }
    return el('div', { class: 'card' }, el('h2', {}, 'Security analysis'),
      el('h3', {}, 'Attack tests in this browser'),
      el('p', { class: 'muted' }, 'Builds a throw-away transfer between two new keys, then tries to break it ten ways: flipping bits, changing the IV or tag, cutting blocks off, corrupting the key or signature, and using the wrong private key.'),
      el('div', { class: 'row' }, run), status, tamperBox,
      el('h3', {}, 'Attack scenarios against the running application'),
      el('p', { class: 'muted' }, 'Authentication, authorization, replay, injection, tampering, robustness and audit-log attacks, each run against the real server.'), suite,
      el('h3', {}, 'Algorithms and strength'), el('div', { class: 'tablewrap' }, ctx.table(['Purpose', 'Algorithm', 'How it is used', 'Strength'], ALGOS, 'plain')),
      el('h3', {}, 'Who can do what'), el('div', { class: 'tablewrap' }, ctx.table(['Attacker', 'What they get', 'What they cannot do', 'Evidence'], THREATS, 'plain')),
      el('h3', {}, 'Known limitations'), el('ul', { class: 'limits' }, LIMITS.map(t => el('li', {}, t))));
  }

  // ---- 5. packet capture
  async function captureCard(ctx, rep) {
    const { el } = ctx;
    if (!rep) return el('div', { class: 'card' }, el('h2', {}, 'Packet capture'),
      el('p', { class: 'muted' }, 'Records the same transfer three ways with a packet sniffer and shows what an eavesdropper could read.'),
      noReport(ctx, 'python scripts/capture_packets.py'),
      el('p', { class: 'muted small' }, 'Needs Wireshark (or tcpdump) and administrator/root rights.'));
    const r = rep.report, S = r.scenarios;
    const cell = (f) => !f.applicable ? el('span', { class: 'pill na' }, 'n/a') : f.visible ? el('span', { class: 'pill bad' }, '✖ Visible') : el('span', { class: 'pill good' }, '✔ Hidden');
    const matrix = el('div', { class: 'tablewrap' }, ctx.table(['What an eavesdropper looks for', ...S.map(s => s.id + '  ' + s.title)],
      S[0].findings.map((f, i) => [el('div', {}, el('div', { class: 'tl' }, f.label), el('div', { class: 'muted small' }, f.meaning)), ...S.map(s => cell(s.findings[i]))]), 'matrix'));
    const facts = el('div', { class: 'tablewrap' }, ctx.table(['Scenario', 'Packets', 'Bytes on the wire', 'Overhead over the ' + sizeLabel(r.evidence_bytes) + ' file', 'Protocols seen', 'Encryption on the wire'],
      S.map(s => [s.id + '  ' + s.title, s.packets, s.wire_bytes.toLocaleString(), ((s.wire_bytes / s.plaintext_bytes - 1) * 100).toFixed(1) + '%',
        Object.entries(s.protocols).map(([k, v]) => k + ' ×' + v).join(', '), s.tls ? s.tls.version + ', ' + s.tls.cipher_suite : 'None (plain HTTP)']), 'plain'));
    const dl = (s) => el('button', { class: 'ghost', onclick: async (ev) => {
      try { const blob = await ctx.api('/api/captures/' + s.pcap.split('/').pop()).then(x => x.blob()), url = URL.createObjectURL(blob), a = document.createElement('a');
        a.href = url; a.download = s.pcap.split('/').pop(); a.click(); setTimeout(() => URL.revokeObjectURL(url), 4000); } catch (e) { ev.target.textContent = 'Download failed'; } } }, 'Download ' + s.pcap.split('/').pop());
    const views = S.map(s => el('details', { class: 'inner capture', open: s.id === 'B' ? '' : null },
      el('summary', {}, s.id + '  ' + s.title + ' (' + s.packets + ' packets)'),
      el('div', { class: 'hexhead' }, 'First bytes the client sent (like Wireshark’s “Follow TCP stream”)'),
      el('pre', { class: 'hex stream', tabindex: '0' }, s.stream_excerpt.client_to_server || '(nothing)'),
      s.summary_lines.length ? el('div', { class: 'tablewrap' }, ctx.table(['No.', 'Time (s)', 'Length', 'Protocol', 'Info'], s.summary_lines.map(x => [x.no, x.t, x.length, x.proto, x.info]), 'plain')) : null,
      el('div', { class: 'row actions' }, dl(s))));
    return el('div', { class: 'card' }, el('h2', {}, 'Packet capture'),
      el('p', { class: 'muted' }, 'The same transfer of one ' + sizeLabel(r.evidence_bytes) + ' text file, recorded three ways by a packet sniffer (' + r.tool + ', interface ' + r.interface + ') and then searched byte by byte. Captured ' + when(r.generated_at) + ' on ' + r.platform + '.'),
      el('h3', {}, 'What could be read'), matrix,
      el('ul', { class: 'findings' }, r.key_findings.map(t => el('li', {}, t))),
      el('h3', {}, 'Traffic summary'), facts,
      el('h3', {}, 'The captured packets'), ...views,
      el('h3', {}, 'Capture it yourself'),
      el('ol', { class: 'howto' }, [el('li', {}, 'Run  python scripts/capture_packets.py  as administrator (Windows: Wireshark with Npcap installed).'), ...r.how_to.map(t => el('li', {}, t))]),
      el('p', { class: 'muted small' }, r.note));
  }

  // ------------------------------------------------------------------ entry point
  async function build(ctx) {
    const [bench, sec, cap] = await Promise.all([getReport(ctx, 'benchmark'), getReport(ctx, 'security'), getReport(ctx, 'capture')]);
    const jump = ctx.el('nav', { class: 'jump', 'aria-label': 'On this page' }, [['m-times', 'Real transfers'], ['m-size', 'Time vs length'], ['m-sig', 'Signatures'], ['m-sec', 'Security'], ['m-cap', 'Packet capture']].map(
      ([id, t]) => ctx.el('a', { href: '#' + id, onclick: (e) => { e.preventDefault(); const n = document.getElementById(id); if (n) n.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }, t)));
    const tag = (id, c) => { c.id = id; return c; };
    return [jump, tag('m-times', await measurementsCard(ctx)), tag('m-size', await sizeChartCard(ctx, bench)), tag('m-sig', await signatureCard(ctx, bench)),
      tag('m-sec', await securityCard(ctx, sec)), tag('m-cap', await captureCard(ctx, cap))];
  }

  window.EVAnalysis = { build, encryptionReport, decryptionSection, ciphertextView, hexdump, fmtMs, sizeLabel };
})();
