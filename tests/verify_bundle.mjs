/* Artifact test — loads the BUILT bundle (assets/js/spv2-core.js), i.e.
 * the exact file the browser and worker execute, and re-checks the
 * original vectors through it. Guards against build/bundling drift.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const bundlePath = path.join(here, '..', 'assets', 'js', 'spv2-core.js');
const code = fs.readFileSync(bundlePath, 'utf8');

// Evaluate the IIFE exactly as a classic <script>/importScripts() would,
// with `self` provided (WorkerGlobalScope is undefined in Node, so the
// worker auto-attach must NOT fire here).
const sandbox = {};
const factory = new Function('self', `${code}; return self.spv2CoreFactory;`)(sandbox);

if (typeof factory !== 'function') {
    console.error('FAIL: bundle does not expose spv2CoreFactory on self');
    process.exit(1);
}
if (typeof WorkerGlobalScope !== 'undefined') {
    console.error('FAIL: unexpected WorkerGlobalScope in Node test env');
    process.exit(1);
}
console.log('PASS bundle exposes spv2CoreFactory');

const vectors = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8'));
const engine = factory(null, false);

let failed = 0;
for (const v of vectors) {
    const [master, code2, tier, counter, length, mode] = v.args;
    const out = await engine.derive({ master, code: code2, tier, counter, length, mode });
    if (out.password !== v.pwd) {
        console.error('FAIL', v.args, out.password, '!=', v.pwd);
        failed++;
    }
}
// cache path: single-slot cache holds the MOST RECENT (master, code, tier)
// exactly like the original — re-derive the last vector, which must hit.
const last = vectors[vectors.length - 1];
const tHit = Date.now();
const again = await engine.derive({
    master: last.args[0], code: last.args[1], tier: last.args[2],
    counter: last.args[3], length: last.args[4], mode: last.args[5],
});
const hitMs = Date.now() - tHit;
if (again.password !== last.pwd) { console.error('FAIL cached re-derive'); failed++; }
else if (again.cached !== true) { console.error('FAIL expected cached=true'); failed++; }
else console.log(`PASS session cache reuse (${hitMs}ms, no Argon2 re-run)`);

if (failed) process.exit(1);
// The WASM fast path must have passed its boot cross-KAT in this
// environment (vendored provider is always present in the repo); a
// silent drop to noble-only would mean the bundle's provider gate broke.
const provider = engine.provider();
if (provider !== 'hash-wasm') {
    console.error(`FAIL: expected Argon2id provider 'hash-wasm', got '${provider}'`);
    process.exit(1);
}
console.log(`PASS provider gate: ${provider}`);
console.log(`ALL ${vectors.length} VECTORS PASSED THROUGH THE BUILT BUNDLE`);
