/* Compare the exact vendored provider shipped in the production bundle to
 * the pinned @noble/hashes implementation. Missing providers are test failures,
 * never a green SKIP. HASHWASM_DIST remains a developer-only comparison override.
 */
import { argon2id as noble } from '@noble/hashes/argon2.js';
import vendor from '../vendor/hash-wasm/argon2.umd.min.cjs';
const enc = new TextEncoder();
const hw = process.env.HASHWASM_DIST
    ? (await import(process.env.HASHWASM_DIST)).argon2id
    : vendor.argon2id;
if (typeof hw !== 'function') throw new Error('Vendored Argon2id provider missing');

/* Salt framing replicated from src/spv2-core.mjs (spec is frozen and is
 * itself guarded by tests/golden.json — both providers receive the same
 * bytes here, so this only flavours the inputs). */
const DOMAIN_SALT = enc.encode('StarryPass-v2:salt\x00');
const DOMAIN_AD = enc.encode('StarryPass-v2:argon2id-ad:v1');
async function buildSalt(code, tierId) {
    const cb = enc.encode(code.trim().normalize('NFC'));
    const saltIn = new Uint8Array(DOMAIN_SALT.length + 4 + cb.length + 1);
    saltIn.set(DOMAIN_SALT, 0);
    new DataView(saltIn.buffer).setUint32(DOMAIN_SALT.length, cb.length, true);
    saltIn.set(cb, DOMAIN_SALT.length + 4);
    saltIn[saltIn.length - 1] = tierId;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', saltIn));
}

// 1. RFC 9106 §5.3 KAT with secret + ad
const kat = await hw({
    password: new Uint8Array(32).fill(1), salt: new Uint8Array(16).fill(2),
    secret: new Uint8Array(8).fill(3), ad: new Uint8Array(12).fill(4),
    parallelism: 4, iterations: 3, memorySize: 32, hashLength: 32, outputType: 'hex',
});
if (kat !== '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659') {
    console.error('FAIL RFC 9106 KAT:', kat);
    process.exit(1);
}
console.log('PASS RFC 9106 §5.3 KAT (secret + ad)');

// 2. Production tag parity
const TIERS = { standard: { id: 1, m: 65536, t: 3, p: 4 }, paranoid: { id: 2, m: 262144, t: 4, p: 4 } };
const combos = [
    ['correct horse battery staple', 'github', 'standard'],
    ['星垂平野阔，月涌大江流！2026', '豆瓣', 'standard'],
    ['café-secret', 'proton', 'standard'],
    ['银行卡主口令#9527', 'cmb-card', 'paranoid'],
];
let failed = 0;
for (const [master, code, tierName] of combos) {
    const T = TIERS[tierName];
    const salt = await buildSalt(code, T.id);
    const pw = enc.encode(master.normalize('NFC'));
    const a = noble(pw, salt, { t: T.t, m: T.m, p: T.p, dkLen: 32, version: 0x13, personalization: DOMAIN_AD });
    const b = await hw({ password: pw, salt, ad: DOMAIN_AD, iterations: T.t, memorySize: T.m, parallelism: T.p, hashLength: 32, outputType: 'binary' });
    const eq = Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
    console.log(`${eq ? 'PASS' : 'FAIL'} tag parity [${tierName}] ${JSON.stringify(code)}`);
    if (!eq) failed++;
}

// 3. Benchmark (informational)
const pw = enc.encode('correct horse battery staple');
const salt = await buildSalt('github', 1);
let t0 = performance.now();
await hw({ password: pw, salt, ad: DOMAIN_AD, iterations: 3, memorySize: 65536, parallelism: 4, hashLength: 32, outputType: 'binary' });
const hwStd = performance.now() - t0;
t0 = performance.now();
noble(pw, salt, { t: 3, m: 65536, p: 4, dkLen: 32, version: 0x13, personalization: DOMAIN_AD });
const nbStd = performance.now() - t0;
console.log(`bench standard: hash-wasm ${hwStd.toFixed(0)}ms vs noble ${nbStd.toFixed(0)}ms (${(nbStd / hwStd).toFixed(1)}x)`);

if (failed) { console.error(`${failed} parity case(s) FAILED`); process.exit(1); }
console.log('ALL PARITY CHECKS PASSED');
