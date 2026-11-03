// Node harness: runs the browser crypto's timing + explicit tamper test on a throw-away transfer.
const E = require('../static/crypto.js');
(async () => {
  const b = await E.selfTestBundle();
  const opened = await E.openEnvelope(b.meta, b.blob, b.privPem);
  const attacks = await E.tamperTest(b.meta, b.blob, b.privPem);
  console.log(JSON.stringify({ sendTimings: b.timings, receiveTimings: opened.report.timings, attacks }));
})().catch(e => { console.error('ERROR: ' + e.message); process.exit(1); });
