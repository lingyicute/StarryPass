/* Golden-set GENERATOR (dev-only, run manually):
 *
 *   ORIG_CORE=/path/to/original/assets/js/spv2-core.js node tests/generate_golden.mjs
 *
 * Runs the ORIGINAL hand-rolled StarryPass v2 core over a broad set of
 * edge cases (normalisation, clamping, mode/tier boundaries, errors) and
 * records the outputs into tests/golden.json. The production core must
 * reproduce this file byte-for-byte.
 *
 * The original core is NOT shipped in this repository; it lives in the
 * upstream StarryPass repository history (pre-production tag / main
 * before the production rewrite).
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const origPath = process.env.ORIG_CORE;
if (!origPath) {
    console.error('Set ORIG_CORE=/path/to/original/spv2-core.js');
    process.exit(2);
}

const require = createRequire(import.meta.url);
const { spv2CoreFactory } = require(path.resolve(origPath));
const engine = spv2CoreFactory(null, false);

const CASES = [
    /* --- normalisation & unicode --- */
    { master: 'café-secret', code: 'proton', tier: 'standard', counter: 1, length: 16, mode: 'full' },
    { master: 'café-secret', code: 'proton', tier: 'standard', counter: 1, length: 16, mode: 'full' },   // NFD twin
    { master: 'ﬁx me not', code: 'ligature', tier: 'standard', counter: 1, length: 16, mode: 'full' },
    { master: '🦄🔒-master-2026', code: 'emoji-site', tier: 'standard', counter: 1, length: 20, mode: 'full' },
    { master: 'مرحبا بالعالم-主密码', code: 'rtl', tier: 'standard', counter: 1, length: 16, mode: 'alnum' },
    { master: 'Ａｌｌ－ｗｉｄｔｈ　ｍａｓｔｅｒ', code: 'fullwidth', tier: 'standard', counter: 1, length: 16, mode: 'full' },
    { master: '  leading and trailing  ', code: 'x', tier: 'standard', counter: 1, length: 16, mode: 'full' }, // master NOT trimmed
    { master: 'm', code: '  internal  spaces  ', tier: 'standard', counter: 1, length: 16, mode: 'full' },    // code only trimmed
    { master: 'repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat-repeat', code: 'long-master', tier: 'standard', counter: 1, length: 16, mode: 'full' },
    { master: 'm', code: 'a-very-long-site-code-that-goes-on-and-on-and-on-and-on-and-on-and-on-2026', tier: 'standard', counter: 1, length: 16, mode: 'full' },

    /* --- counter clamping --- */
    { master: 'm1', code: 'counter', tier: 'standard', counter: 0, length: 16, mode: 'full' },
    { master: 'm1', code: 'counter', tier: 'standard', counter: -3, length: 16, mode: 'full' },
    { master: 'm1', code: 'counter', tier: 'standard', counter: 9999, length: 16, mode: 'full' },
    { master: 'm1', code: 'counter', tier: 'standard', counter: 10000, length: 16, mode: 'full' },
    { master: 'm1', code: 'counter', tier: 'standard', counter: 'abc', length: 16, mode: 'full' },
    { master: 'm1', code: 'counter', tier: 'standard', counter: 7.9, length: 16, mode: 'full' },
    { master: 'm1', code: 'counter', tier: 'standard', counter: null, length: 16, mode: 'full' },

    /* --- length clamping & defaults --- */
    { master: 'm2', code: 'length', tier: 'standard', counter: 1, length: 3, mode: 'full' },     // -> 4
    { master: 'm2', code: 'length', tier: 'standard', counter: 1, length: 100, mode: 'full' },   // -> 64
    { master: 'm2', code: 'length', tier: 'standard', counter: 1, length: '20', mode: 'full' },
    { master: 'm2', code: 'length', tier: 'standard', counter: 1, length: null, mode: 'full' },  // -> 16
    { master: 'm2', code: 'length', tier: 'standard', counter: 1, length: 4, mode: 'full' },     // min boundary, all req classes
    { master: 'm2', code: 'length', tier: 'standard', counter: 1, length: 64, mode: 'full' },    // max boundary

    /* --- mode boundaries --- */
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 4, mode: 'alnum' },
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 63, mode: 'alnum' },
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 4, mode: 'pin' },
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 8, mode: 'pin' },
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 64, mode: 'pin' },
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 16, mode: 'bogus' },    // -> full
    { master: 'm3', code: 'mode', tier: 'standard', counter: 1, length: 16 },                   // -> full

    /* --- tier defaults / paranoid --- */
    { master: 'm4', code: 'tier', tier: 'ultra', counter: 1, length: 16, mode: 'full' },        // -> standard
    { master: 'm4', code: 'tier', tier: 'standard', counter: 1, length: 16, mode: 'full' },
    { master: 'm4', code: 'tier', tier: 'paranoid', counter: 1, length: 16, mode: 'full' },
    { master: 'm4', code: 'tier', tier: 'paranoid', counter: 5, length: 24, mode: 'alnum' },

    /* --- rotation / sharing semantics --- */
    { master: 'shared-master#77', code: 'bank', tier: 'standard', counter: 1, length: 20, mode: 'full' },
    { master: 'shared-master#77', code: 'bank', tier: 'standard', counter: 2, length: 20, mode: 'full' },
    { master: 'shared-master#77', code: 'forum', tier: 'standard', counter: 1, length: 20, mode: 'full' },
    { master: 'shared-master#77', code: 'BANK', tier: 'standard', counter: 1, length: 20, mode: 'full' }, // case-sensitive code

    /* --- CJK-heavy inputs --- */
    { master: '星垂平野阔，月涌大江流！2026', code: '豆瓣', tier: 'standard', counter: 3, length: 16, mode: 'full' },
    { master: '星垂平野阔，月涌大江流！2026', code: '知乎', tier: 'standard', counter: 1, length: 24, mode: 'alnum' },
    { master: '银行卡主口令#9527', code: 'cmb-card', tier: 'paranoid', counter: 1, length: 6, mode: 'pin' },

    /* --- error parity --- */
    { master: '', code: 'github', tier: 'standard', counter: 1, length: 16, mode: 'full', error: 'EMPTY_INPUT' },
    { master: 'x', code: '   ', tier: 'standard', counter: 1, length: 16, mode: 'full', error: 'EMPTY_INPUT' },
    { master: '', code: '', tier: 'standard', counter: 1, length: 16, mode: 'full', error: 'EMPTY_INPUT' },
];

const cases = [];
let n = 0;
for (const c of CASES) {
    const { error, ...args } = c;
    n++;
    if (error) {
        try {
            engine.deriveSync(args);
            console.error(`FAIL case ${n}: expected ${error}`);
            process.exit(1);
        } catch (err) {
            if (err.message !== error) {
                console.error(`FAIL case ${n}: got error ${err.message}, want ${error}`);
                process.exit(1);
            }
            cases.push({ args: c, error });
            console.log(`case ${n}: error ${error} ✓`);
        }
    } else {
        const r = engine.deriveSync(args);
        cases.push({ args: c, pwd: r.password });
        console.log(`case ${n}: ${r.password} ✓`);
    }
}

const out = {
    provenance: 'Generated by tests/generate_golden.mjs from the ORIGINAL hand-rolled StarryPass v2 core (pre-production implementation).',
    cases,
};
const dest = path.join(path.dirname(fileURLToPath(import.meta.url)), 'golden.json');
fs.writeFileSync(dest, JSON.stringify(out, null, 2) + '\n');
console.log(`\n${cases.length} golden cases written to ${dest}`);
