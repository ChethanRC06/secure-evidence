// Node harness: runs the SAME static/crypto.js the browser uses, against the live server.
//   node js_interop.js receive <server> <user> <password> <keyfile> <transferId> <outfile>
//   node js_interop.js send    <server> <user> <password> <keyfile> <recipient> <infile>
const fs = require('fs'), E = require('../static/crypto.js');
const [mode, server, user, pw, keyfile, arg, file] = process.argv.slice(2);
(async () => {
  const j = async (r) => { const t = await r.json(); if (!r.ok) throw new Error(`HTTP ${r.status}: ${t.error}`); return t; };
  const { token } = await j(await fetch(server + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: user, password: pw }) }));
  const H = { Authorization: 'Bearer ' + token }, priv = fs.readFileSync(keyfile, 'utf8');
  if (mode === 'receive') {
    const meta = await j(await fetch(`${server}/api/transfers/${arg}`, { headers: H }));
    const blob = new Uint8Array(await (await fetch(`${server}/api/transfers/${arg}/ciphertext`, { headers: H })).arrayBuffer());
    const { plain, report } = await E.openEnvelope(meta, blob, priv);
    fs.writeFileSync(file, plain); console.log(JSON.stringify(report));
  } else if (mode === 'send') {
    const { recipients } = await j(await fetch(server + '/api/recipients', { headers: H }));
    const rcp = recipients.find(r => r.username === arg);
    const { fields, blob } = await E.buildTransfer({ username: user, privPem: priv, recipient: rcp, data: new Uint8Array(fs.readFileSync(file)), filename: require('path').basename(file), mime: 'application/octet-stream' });
    const fd = new FormData(); Object.entries(fields).forEach(([k, v]) => fd.append(k, v)); fd.append('ciphertext', new Blob([blob]), 'evidence.bin');
    console.log(JSON.stringify(await j(await fetch(server + '/api/transfers', { method: 'POST', headers: H, body: fd }))));
  }
})().catch(e => { console.error('ERROR: ' + e.message); process.exit(1); });
