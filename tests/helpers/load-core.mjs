/* Test-only loader: executes the real source in the current realm (not a slow VM).
 * Imports are injected to permit deterministic provider/WebCrypto fault tests.
 * No probes or dependency substitutions enter the shipped bundle.
 */
import fs from 'node:fs';
import { webcrypto } from 'node:crypto';
import { argon2id, argon2idAsync } from '@noble/hashes/argon2.js';
import vendor from '../../vendor/hash-wasm/argon2.umd.min.cjs';

export function loadCore(options = {}) {
    let source = fs.readFileSync(options.source || new URL('../../src/spv2-core.mjs', import.meta.url), 'utf8');
    let count = 0;
    source = source.replace(/^import [^\n]+;\r?\n/gm, () => { count++; return ''; });
    if (count !== 2) throw new Error('core import probe boundary changed');
    source = source.replace('export function spv2CoreFactory', 'function spv2CoreFactory');
    const crypto = options.crypto || webcrypto;
    const host = { crypto };
    const self = {};
    const run = new Function('globalThis', 'self', 'TextEncoder', 'console',
        'argon2id', 'argon2idAsync', 'hashwasmArgon2Module', source + '\nreturn { spv2CoreFactory, HkdfStream, buildSalt, computeSessionTag, canonicalizeInputs };');
    return run(host, self, options.TextEncoder || TextEncoder, options.console || console,
        options.argon2id || argon2id, options.argon2idAsync || argon2idAsync,
        Object.hasOwn(options, 'provider') ? options.provider : vendor);
}

export function cryptoProbe() {
    const state = { fail: null, encoded: [], messages: [], rawBlocks: [], digestInputs: [], random: [], hmacKeys: [], hkdfKeys: [] };
    const subtle = {};
    for (const name of ['digest', 'importKey', 'sign', 'deriveBits']) {
        subtle[name] = async (...args) => {
            if (name === 'digest') state.digestInputs.push(args[1]);
            if (name === 'sign') state.messages.push(args[2]);
            if (name === 'importKey' && args[2]?.name === 'HMAC') state.hmacKeys.push(args[1]);
            if (name === 'importKey' && args[2] === 'HKDF') state.hkdfKeys.push(args[1]);
            if (state.fail === name || (typeof state.fail === 'function' && state.fail(name, args))) throw new Error('INJECTED_' + name);
            const out = await webcrypto.subtle[name](...args);
            if (name === 'deriveBits') state.rawBlocks.push(new Uint8Array(out));
            return out;
        };
    }
    const crypto = {
        subtle,
        getRandomValues(bytes) {
            state.random.push(bytes);
            if (state.fail === 'random') { bytes[0] = 99; throw new Error('INJECTED_random'); }
            return webcrypto.getRandomValues(bytes);
        },
    };
    class TrackingEncoder extends TextEncoder {
        encode(value) { const bytes = super.encode(value); state.encoded.push(bytes); return bytes; }
    }
    return { state, crypto, TextEncoder: TrackingEncoder };
}
