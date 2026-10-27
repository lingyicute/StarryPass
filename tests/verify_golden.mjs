/* Compat test #2 — golden set produced by the ORIGINAL hand-rolled core.
 * See tests/generate_golden.mjs for provenance.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spv2CoreFactory } from '../src/spv2-core.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const { cases } = JSON.parse(fs.readFileSync(path.join(here, 'golden.json'), 'utf8'));

const engine = spv2CoreFactory(null, false);

let failed = 0, passed = 0;
const t0 = Date.now();
for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    if (c.error) {
        try {
            await engine.derive(c.args);
            console.error(`FAIL #${i + 1}: expected error ${c.error}`);
            failed++;
        } catch (err) {
            if (err.message === c.error) passed++;
            else { console.error(`FAIL #${i + 1}: got ${err.message}, want ${c.error}`); failed++; }
        }
    } else {
        const r = await engine.derive(c.args);
        if (r.password !== c.pwd) {
            console.error(`FAIL #${i + 1}`, JSON.stringify(c.args), `\n  got     ${r.password}\n  expected ${c.pwd}`);
            failed++;
        } else {
            passed++;
            process.stdout.write('.');
        }
    }
}

const secs = ((Date.now() - t0) / 1000).toFixed(1);
if (failed) { console.error(`\n${failed}/${cases.length} golden case(s) FAILED (${secs}s)`); process.exit(1); }
console.log(`\nALL ${passed} GOLDEN CASES MATCH THE ORIGINAL IMPLEMENTATION (${secs}s)`);
