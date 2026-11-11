'use strict';
/*
 * server.js — Remote victim for GHSA-673q-mjm6-r5xr / CVE-2026-126187
 *             "Unauthenticated RCE in `use cache` functions returning typed arrays"
 *
 * This HTTP server is a faithful, minimal reproduction of the Next.js 16.x
 * App Router "use cache" (Cache Components) serialization boundary. It uses the
 * EXACT React Server Components Flight code that Next.js 16.4.0 bundles
 * (react-server-dom-webpack — pinned by the Dockerfile build arg), so the bug,
 * the wire format and the fix are all the real thing.
 *
 * ---------------------------------------------------------------------------
 * How this maps to real Next.js (dist/server/use-cache/use-cache-wrapper.js):
 *
 *   PRODUCER ("cache write")  Next:  renderToReadableStream(resultPromise,
 *                                        clientReferenceManifest.clientModules,
 *                                        { environmentName: 'Cache', ... })
 *                             here:  renderToReadableStream(value, CLIENT_MODULES,
 *                                        { environmentName: 'Cache' })
 *
 *   STORE                     Next:  stream.tee() -> cache handler keeps the bytes
 *                             here:  drain(stream) -> Buffer  (the cached entry)
 *
 *   CONSUMER ("cache read")   Next:  createFromReadableStream(cachedStream,
 *                                        { serverConsumerManifest, ... })
 *                             here:  createFromReadableStream(cachedStream,
 *                                        { serverConsumerManifest })
 *
 * The decode happens IN THE SERVER PROCESS while rendering the page, so any code
 * execution it triggers is server-side and unauthenticated.
 *
 * ---------------------------------------------------------------------------
 * The vulnerable application pattern (`getProfileCard` below):
 *
 *   A `use cache` function returns MULTIPLE typed arrays that are VIEWS ONTO THE
 *   SAME ArrayBuffer (here: an `avatar` region and a `thumbnail` region sliced
 *   from one decoded-image buffer — an extremely common "decode once, slice
 *   regions" pattern) PLUS an attacker-controlled value (`displayName`, taken
 *   straight from the request).
 *
 *   React's Flight encoder emits large typed arrays "by reference" into a byte
 *   ReadableStream. Enqueuing the first view DETACHES the shared ArrayBuffer
 *   (per the WHATWG Streams "transfer" semantics), so the second view's
 *   byteLength silently becomes 0 — AFTER its chunk header already declared the
 *   original length. The decoder then reads the declared number of bytes from
 *   the following stream content, swallowing subsequent framing and letting the
 *   attacker-controlled `displayName` bytes be parsed as raw Flight protocol
 *   rows. Those injected rows introduce a Server Reference the attacker chose.
 */

const http = require('node:http');
const { renderToReadableStream } = require('react-server-dom-webpack/server.node');
const { createFromReadableStream } = require('react-server-dom-webpack/client.node');
const { serverConsumerManifest, CLIENT_MODULES, state } = require('./app-modules');

const PORT = Number(process.env.PORT || 3000);
const RSDW_VERSION = require('react-server-dom-webpack/package.json').version;

// Size of each typed-array view. >4096 bytes => React emits it "by reference"
// (streamed straight into the byte stream), which is the detach-prone path.
const VIEW_BYTES = 8192;

// ---------------------------------------------------------------------------
// The vulnerable `use cache` function.
// Returns two typed-array views over ONE ArrayBuffer + an attacker value.
// ---------------------------------------------------------------------------
function getProfileCard(displayName) {
  // 'use cache'  <-- in real Next.js this directive caches the return value and
  //                  routes it through the Flight encode/decode boundary above.
  const decodedImage = new ArrayBuffer(VIEW_BYTES * 2);        // one decoded image
  const avatar = new Uint8Array(decodedImage, 0, VIEW_BYTES);  // region 1 (view)
  const thumbnail = new Uint8Array(decodedImage, VIEW_BYTES, VIEW_BYTES); // region 2 (SAME buffer)
  avatar.fill(0x41);     // 'A' — pretend pixel data
  thumbnail.fill(0x42);  // 'B'
  // Key order matters: the attacker value is serialized AFTER both typed arrays.
  return { avatar, thumbnail, displayName };
}

// Drain a ReadableStream (Uint8Array chunks) into one Buffer — the "cache write".
async function drain(stream) {
  const reader = stream.getReader();
  const chunks = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
  }
  return Buffer.concat(chunks);
}

// Wrap bytes back into a ReadableStream — the "cache read".
function bytesToStream(buf) {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(buf));
      controller.close();
    },
  });
}

// The full `use cache` round trip: encode -> store -> decode (all server-side).
//
// Note: a successful injection hijacks the root chunk into a thenable whose
// `.then` is the attacker's Server Reference. That reference executes the
// payload synchronously but never resolves the chunk, so the decode promise
// would hang. We race it against a short timeout: by the time the timeout
// fires, the server-side code execution has already happened. (A real page
// render has the same property — the payload runs before the render settles.)
async function renderThroughUseCache(value, timeoutMs = 2000) {
  const stream = renderToReadableStream(value, CLIENT_MODULES, { environmentName: 'Cache' });
  const cachedBytes = await drain(stream);                       // stored cache entry
  // createFromReadableStream returns a custom thenable (ReactPromise). Awaiting
  // it coerces it (calling its .then) — which is exactly what invokes the
  // injected Server Reference. We wrap that await so a hijacked, never-settling
  // root cannot hang the request.
  const decodePromise = createFromReadableStream(bytesToStream(cachedBytes), {
    serverConsumerManifest,                                      // cache read / rehydrate
  });
  const settled = (async () => {
    try { return { value: await decodePromise }; }
    catch (e) { return { error: e }; }
  })();
  const decoded = await Promise.race([
    settled,
    new Promise((r) => setTimeout(() => r({ timedOut: true }), timeoutMs)),
  ]);
  return { decoded, cachedBytes };
}

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve, reject) => {
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res, code, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

const LANDING = `GHSA-673q-mjm6-r5xr victim (react-server-dom-webpack@${RSDW_VERSION})

This service caches a user "profile card" with Next.js-style "use cache".
The cached value bundles two image buffers (avatar + thumbnail, sliced from one
decoded image) and a user-supplied display name.

Endpoints:
  GET  /                 this text
  GET  /health           liveness
  POST /profile          body = raw displayName; returns the rendered card
  GET  /proof            last server-side command execution (empty until exploited)

Try a normal request:
  curl -s -XPOST --data 'Ada Lovelace' http://localhost:${PORT}/profile
`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end(LANDING);
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { ok: true, rsdw: RSDW_VERSION, pid: process.pid });
    }

    if (req.method === 'GET' && url.pathname === '/proof') {
      return json(res, 200, {
        exploited: state.lastProof != null,
        invocations: state.invocations,
        proof: state.lastProof,
      });
    }

    if (req.method === 'POST' && url.pathname === '/profile') {
      // The attacker-controlled value flows straight into the cached function.
      const displayName = await readBody(req);
      let decodedSummary = null;
      let decodeStatus = null;
      try {
        const { decoded } = await renderThroughUseCache(getProfileCard(displayName));
        if (decoded.timedOut) {
          // Root chunk hijacked into a never-settling thenable (payload already ran).
          decodeStatus = 'timed-out (root chunk hijacked)';
        } else if (decoded.error) {
          decodeStatus = 'error: ' + String(decoded.error.message || decoded.error).slice(0, 160);
        } else {
          const v = decoded.value;
          decodeStatus = 'ok';
          decodedSummary = {
            keys: v && typeof v === 'object' ? Object.keys(v) : typeof v,
            displayName: v && typeof v.displayName === 'string' ? v.displayName.slice(0, 64) : undefined,
          };
        }
      } catch (e) {
        decodeStatus = 'throw: ' + String((e && e.message) || e).slice(0, 160);
      }
      return json(res, 200, {
        ok: true,
        rsdw: RSDW_VERSION,
        displayNameBytes: Buffer.byteLength(displayName),
        decoded: decodedSummary,
        decodeStatus,
        codeExecutionObserved: state.lastProof != null,
      });
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
  } catch (e) {
    json(res, 500, { error: String((e && e.stack) || e) });
  }
});

server.listen(PORT, () => {
  console.log(`[victim] react-server-dom-webpack@${RSDW_VERSION} listening on :${PORT} (pid ${process.pid})`);
});
