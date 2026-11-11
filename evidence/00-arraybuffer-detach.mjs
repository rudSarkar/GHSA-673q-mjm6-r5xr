// 00 — the WHATWG primitive the whole bug rests on.
//
// Enqueuing a typed-array view into a byte ReadableStream TRANSFERS (detaches)
// its backing ArrayBuffer. Every other view onto that same buffer then reports
// byteLength 0 — which is how a second typed array silently becomes empty while
// its Flight chunk header has already declared the original length.
//
// Run:  node 00-arraybuffer-detach.mjs
const buf = new ArrayBuffer(16384);
const v1 = new Uint8Array(buf, 0, 8192);       // view A
const v2 = new Uint8Array(buf, 8192, 8192);    // view B — SAME backing buffer
v1.fill(0x41);
v2.fill(0x42);

let ctrl;
const rs = new ReadableStream({ type: 'bytes', start(c) { ctrl = c; } });

console.log('before enqueue: buf.detached =', buf.detached,
            '| v1.byteLength =', v1.byteLength, '| v2.byteLength =', v2.byteLength);
ctrl.enqueue(v1);
console.log('after  enqueue: buf.detached =', buf.detached,
            '| v1.byteLength =', v1.byteLength, '| v2.byteLength =', v2.byteLength);

console.log('\n>>> VERDICT:', buf.detached
  ? 'DETACHED — a second view now reports 0 bytes, so the encoder writes 0 bytes for a header that already declared 8192.'
  : 'not detached (unexpected on this runtime)');
