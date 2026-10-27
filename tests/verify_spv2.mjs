/* Compat test #1 — the original StarryPass v2 vectors.
 * These expected passwords were produced by the ORIGINAL hand-rolled
 * implementation (spv2-core.js with hand-written SHA-256/HKDF/Argon2id
 * and hand-assembled WASM). Passing means the production core derives
 * byte-identical output.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spv2CoreFactory } from '../src/spv2-core.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8'));

const engine = spv2CoreFactory(null, false);

let failed = 0;
for (const v of vectors) {
    const [master, code, tier, counter, length, mode] = v.args;
    let out;
    try {
        out = await engine.derive({ master, code, tier, counter, length, mode });
    } catch (err) {
        console.error(`FAIL (error ${err.message})`, v.args);
        failed++;
        continue;
    }
    if (out.password !== v.pwd) {
        console.error('FAIL', v.args, '\n  got     ', out.password, '\n  expected', v.pwd);
        failed++;
    } else {
        console.log('PASS', String(mode).padEnd(6), tier.padEnd(9), JSON.stringify(code.trim().slice(0, 16)));
    }
}

// Error-path parity: empty inputs must raise EMPTY_INPUT like the original.
for (const bad of [{ master: '', code: 'github' }, { master: 'x', code: '   ' }]) {
    try {
        await engine.derive({ ...bad, tier: 'standard', counter: 1, length: 16, mode: 'full' });
        console.error('FAIL expected EMPTY_INPUT for', bad);
        failed++;
    } catch (err) {
        if (err.message === 'EMPTY_INPUT') console.log('PASS EMPTY_INPUT rejected');
        else { console.error('FAIL wrong error:', err.message); failed++; }
    }
}

if (failed) { console.error(`\n${failed} vector(s) FAILED`); process.exit(1); }
console.log(`\nALL ${vectors.length} ORIGINAL VECTORS PASSED (bit-compatible with hand-rolled v2)`);
