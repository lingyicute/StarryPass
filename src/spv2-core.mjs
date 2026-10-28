/* StarryPass v2 — production core (compatibility build)
 *
 * Drop-in, bit-compatible with the original hand-rolled StarryPass v2
 * derivation, but with ZERO hand-written cryptographic primitives:
 *
 *   SHA-256 .......... Web Crypto API  (crypto.subtle.digest)
 *   HMAC-SHA-256 ..... Web Crypto API  (crypto.subtle.sign)
 *   HKDF-SHA-256 ..... Web Crypto API  (crypto.subtle.deriveBits, RFC 5869)
 *   Argon2id v1.3 .... @noble/hashes   (RFC 9106, passes §5.3 KAT with
 *                                       secret + associated data)
 *   CSPRNG ........... crypto.getRandomValues
 *
 * Canonicalisation, salt framing, HKDF stream layout and synthesis follow
 * the original v2 specification. Async cache/lifecycle hardening preserves
 * byte-identical passwords for existing normal inputs. The contract is
 * enforced by
 * tests/vectors.json (original vectors) and tests/golden.json (golden set
 * generated with the original implementation).
 *
 * Copyright (C) 2024-2026 lingyicute — AGPL-3.0 (same as StarryPass).
 */

import { argon2id, argon2idAsync } from '@noble/hashes/argon2.js';
import hashwasmArgon2Module from '../vendor/hash-wasm/argon2.umd.min.cjs';

/* Argon2id providers
 * -------------------
 * Primary:  vendored hash-wasm (WASM, ~4.8x faster) — the fork branch
 *           adding the `ad` option StarryPass needs; see vendor/hash-wasm/PROVENANCE.md.
 * Fallback: @noble/hashes (pure JS) — separately KAT-gated, slower.
 *
 * The WASM provider is enabled ONLY after the boot self-test computes
 * the RFC 9106 §5.3 vector with BOTH providers and they agree byte for
 * byte; any mismatch disables it for the session (noble still passes
 * the same KAT, so derivation continues correctly either way).
 */
const hashwasmArgon2id =
    hashwasmArgon2Module && typeof hashwasmArgon2Module.argon2id === 'function'
        ? hashwasmArgon2Module.argon2id
        : hashwasmArgon2Module && hashwasmArgon2Module.default && typeof hashwasmArgon2Module.default.argon2id === 'function'
            ? hashwasmArgon2Module.default.argon2id
            : null;
let wasmProviderEnabled = false;

/* ------------------------------------------------------------------ *
 * Mode / tier tables (must match the v2 spec exactly)                 *
 * ------------------------------------------------------------------ */

const LOWER  = 'abcdefghijklmnopqrstuvwxyz';
const UPPER  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGIT  = '0123456789';
const SYMBOL = '!@#$%^&*()-_=+?';

const MODES = {
    full:  { id: 1, pool: LOWER + UPPER + DIGIT + SYMBOL, req: [LOWER, UPPER, DIGIT, SYMBOL] },
    alnum: { id: 2, pool: LOWER + UPPER + DIGIT, req: [LOWER, UPPER, DIGIT] },
    pin:   { id: 3, pool: DIGIT, req: [DIGIT] },
};

const TIERS = {
    standard: { id: 1, memoryKiB: 65536, passes: 3, parallelism: 4 },
    paranoid: { id: 2, memoryKiB: 262144, passes: 4, parallelism: 4 },
};

const encoder = new TextEncoder();

/* Domain-separation constants — byte-for-byte identical to v2. */
const DOMAIN_SALT    = encodeAscii('StarryPass-v2:salt\x00');
const DOMAIN_AD      = encodeAscii('StarryPass-v2:argon2id-ad:v1');
const DOMAIN_EXTRACT = encodeAscii('StarryPass-v2:hkdf-extract:v1');
const DOMAIN_EXPAND  = encodeAscii('StarryPass-v2:hkdf-expand:v1\x00');
const DOMAIN_CACHE   = encodeAscii('StarryPass-v2:session-cache-tag:v1\x00');

/* HKDF-Expand stream: 255 blocks x 32 bytes (RFC 5869 §2.2 limit). */
const HKDF_MAX_BLOCKS = 255;

function encodeAscii(str) {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0x7f;
    return out;
}

/* ------------------------------------------------------------------ *
 * Small byte helpers (serialization only — no cryptography)           *
 * ------------------------------------------------------------------ */

function zeroize(buf) {
    if (buf && typeof buf.fill === 'function') buf.fill(0);
}

function constantTimeEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
    return diff === 0;
}

function writeLE32(out, offset, val) {
    out[offset]     = val & 0xff;
    out[offset + 1] = (val >>> 8) & 0xff;
    out[offset + 2] = (val >>> 16) & 0xff;
    out[offset + 3] = (val >>> 24) & 0xff;
}

function writeLE16(out, offset, val) {
    out[offset]     = val & 0xff;
    out[offset + 1] = (val >>> 8) & 0xff;
}

function concatBytes(arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let pos = 0;
    for (const a of arrays) { out.set(a, pos); pos += a.length; }
    return out;
}

function lenPrefixed(bytes) {
    const out = new Uint8Array(4 + bytes.length);
    writeLE32(out, 0, bytes.length);
    out.set(bytes, 4);
    return out;
}

/* ------------------------------------------------------------------ *
 * Mature primitives                                                   *
 * ------------------------------------------------------------------ */

const subtle = () => globalThis.crypto.subtle;

async function sha256(bytes) {
    const d = await subtle().digest('SHA-256', bytes);
    return new Uint8Array(d);
}

async function hmacSha256(keyBytes, dataBytes) {
    const key = await subtle().importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await subtle().sign('HMAC', key, dataBytes);
    return new Uint8Array(sig);
}

function validateSessionKey(output) {
    // The frozen protocol requires a 32-byte binary tag. In particular,
    // Uint8Array(32) must never reinterpret a numeric provider error as a key.
    let key;
    if (output instanceof Uint8Array) key = output;
    else if (output instanceof ArrayBuffer) key = new Uint8Array(output);
    else {
        if (ArrayBuffer.isView(output)) {
            zeroize(new Uint8Array(output.buffer, output.byteOffset, output.byteLength));
        }
        throw new Error('INVALID_KDF_OUTPUT');
    }
    if (key.length !== 32) {
        zeroize(key);
        throw new Error('INVALID_KDF_OUTPUT');
    }
    return key;
}

/**
 * Argon2id v1.3 via gated WASM or the @noble/hashes fallback.
 * `secret` is intentionally never set (v2 uses an empty secret);
 * `ad` carries the domain-separation string exactly as the original did.
 * In a dedicated worker we run the synchronous variant (the worker is
 * already off the UI thread); everywhere else we run the async variant
 * which yields periodically so the page stays responsive.
 */
function argon2idDerive({ password, salt, ad, memoryKiB, passes, parallelism, tagLength }, inWorker) {
    if (wasmProviderEnabled && hashwasmArgon2id) {
        return Promise.resolve(
            hashwasmArgon2id({
                password,
                salt,
                ad,
                iterations: passes,
                memorySize: memoryKiB,
                parallelism,
                hashLength: tagLength,
                outputType: 'binary',
            }),
        ).then(validateSessionKey);
    }
    const opts = {
        t: passes,
        m: memoryKiB,
        p: parallelism,
        dkLen: tagLength,
        version: 0x13,
        personalization: ad,
    };
    const pending = inWorker
        ? Promise.resolve(argon2id(password, salt, opts))
        : argon2idAsync(password, salt, { ...opts, asyncTick: 30 });
    return Promise.resolve(pending).then(validateSessionKey);
}

/* ------------------------------------------------------------------ *
 * Stage 1 — salt                                                      *
 * ------------------------------------------------------------------ */

async function buildSalt(codeBytes, tierId) {
    const tierByte = new Uint8Array([tierId]);
    const codeFrame = lenPrefixed(codeBytes);
    let saltIn;
    try {
        saltIn = concatBytes([DOMAIN_SALT, codeFrame, tierByte]);
        return await sha256(saltIn);
    } finally {
        zeroize(saltIn);
        zeroize(codeFrame);
        zeroize(tierByte);
    }
}

/* ------------------------------------------------------------------ *
 * Stage 2 — session cache (same HMAC-over-random-nonce tag as v2)     *
 * ------------------------------------------------------------------ */

async function computeSessionTag(masterBytes, codeBytes, tierId, nonce) {
    const tierByte = new Uint8Array([tierId]);
    const masterFrame = lenPrefixed(masterBytes);
    let codeFrame, msg;
    try {
        codeFrame = lenPrefixed(codeBytes);
        msg = concatBytes([DOMAIN_CACHE, masterFrame, codeFrame, tierByte]);
        return await hmacSha256(nonce, msg);
    } finally {
        zeroize(masterFrame);
        zeroize(codeFrame);
        zeroize(msg);
        zeroize(tierByte);
    }
}

/* ------------------------------------------------------------------ *
 * Stage 3 — HKDF-SHA-256 stream (RFC 5869 on top of Web Crypto)       *
 *                                                                     *
 * T(i) is produced by deriving the first i*32 bytes of the standard   *
 * HKDF-Expand with `info` and taking the last block — byte-identical  *
 * to the original lazy block loop, built purely from subtle.deriveBits.*
 * ------------------------------------------------------------------ */

class HkdfStream {
    constructor(info, codeUnusedGuard) {
        this.info = info;
        this.ikmKey = null;
        this.blockIdx = 0;
        this.buf = new Uint8Array(0);
        this.pos = 0;
        void codeUnusedGuard;
    }

    async init(sk) {
        this.ikmKey = await subtle().importKey('raw', sk, 'HKDF', false, ['deriveBits']);
    }

    async nextByte() {
        if (this.pos >= this.buf.length) {
            this.blockIdx++;
            if (this.blockIdx > HKDF_MAX_BLOCKS) throw new Error('HKDF_EXHAUSTED');
            const bits = await subtle().deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: DOMAIN_EXTRACT, info: this.info },
                this.ikmKey,
                this.blockIdx * 32 * 8
            );
            // deriveBits also returns all preceding blocks: erase that full
            // native result and the replaced block, not just the last slice.
            const raw = new Uint8Array(bits);
            try {
                const next = raw.slice(-32);
                zeroize(this.buf);
                this.buf = next;
                this.pos = 0;
            } finally {
                zeroize(raw);
            }
        }
        return this.buf[this.pos++];
    }

    async uniformInt(n) {
        const limit = 256 - (256 % n);
        for (;;) {
            const b = await this.nextByte();
            if (b < limit) return b % n;
        }
    }

    dispose() {
        zeroize(this.buf);
        this.buf = new Uint8Array(0);
        zeroize(this.info);
        this.info = null;
        this.ikmKey = null;
    }
}

/* ------------------------------------------------------------------ *
 * Stage 4 — zero-bias rejection synthesis (spec logic, verbatim)      *
 * ------------------------------------------------------------------ */

async function synthesizePassword(sk, codeBytes, counter, length, modeName) {
    const modeSpec = MODES[modeName] || MODES.full;
    const meta = new Uint8Array(7);
    writeLE32(meta, 0, counter >>> 0);
    writeLE16(meta, 4, length & 0xffff);
    meta[6] = modeSpec.id;
    const codeFrame = lenPrefixed(codeBytes);
    let info, stream;
    try {
        info = concatBytes([DOMAIN_EXPAND, meta, codeFrame]);
        stream = new HkdfStream(info);
        await stream.init(sk);
        const pool = modeSpec.pool;
        const reqClasses = length >= modeSpec.req.length ? modeSpec.req : [];
        let result = null;

        for (let attempt = 0; attempt < 128; attempt++) {
            const chars = new Array(length);
            for (let i = 0; i < length; i++) chars[i] = pool.charAt(await stream.uniformInt(pool.length));
            const candidate = chars.join('');
            let ok = true;
            for (const cls of reqClasses) {
                let found = false;
                for (let k = 0; k < candidate.length; k++) {
                    if (cls.indexOf(candidate.charAt(k)) !== -1) { found = true; break; }
                }
                if (!found) { ok = false; break; }
            }
            if (ok) { result = candidate; break; }
        }

        if (!result) {
            const arr = [];
            for (const cls of reqClasses) arr.push(cls.charAt(await stream.uniformInt(cls.length)));
            while (arr.length < length) arr.push(pool.charAt(await stream.uniformInt(pool.length)));
            for (let s = length - 1; s > 0; s--) {
                const j = await stream.uniformInt(s + 1);
                const tmp = arr[s]; arr[s] = arr[j]; arr[j] = tmp;
            }
            result = arr.join('');
        }

        return result;
    } finally {
        if (stream) stream.dispose();
        zeroize(info);
        zeroize(codeFrame);
        zeroize(meta);
    }
}

/* ------------------------------------------------------------------ *
 * FIPS 140-3 style power-on self-test (same two KATs as the original) *
 * ------------------------------------------------------------------ */

let selfTestPromise = null;

function runSelfTest(inWorker) {
    if (!selfTestPromise) {
        selfTestPromise = (async () => {
            // 1. RFC 9106 §5.3 Argon2id KAT (exercises secret + AD).
            //    The production path uses an empty secret, but the KAT
            //    must provide one, so it goes through the key variant.
            const p = new Uint8Array(32).fill(1);
            const s = new Uint8Array(16).fill(2);
            const k = new Uint8Array(8).fill(3);
            const x = new Uint8Array(12).fill(4);
            const tagK = await argon2idDeriveWithKey(p, s, k, x, inWorker);
            const expectedA2 = [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
                0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
            ];
            for (let i = 0; i < 32; i++) {
                if (tagK[i] !== expectedA2[i]) throw new Error('KAT_ARGON2ID_FAILED');
            }

            // 3. Cross-provider gate: the vendored hash-wasm (WASM) fast
            //    path is enabled only if it reproduces the same vector
            //    byte for byte. Mismatch disables the fast path.
            if (hashwasmArgon2id) {
                try {
                    const hwTag = await hashwasmArgon2id({
                        password: p, salt: s, secret: k, ad: x,
                        parallelism: 4, iterations: 3, memorySize: 32,
                        hashLength: 32, outputType: 'binary',
                    });
                    const hwBytes = validateSessionKey(hwTag);
                    wasmProviderEnabled = constantTimeEqual(hwBytes, tagK);
                    zeroize(hwBytes);
                } catch {
                    wasmProviderEnabled = false;
                }
            }
            if (!wasmProviderEnabled) {
                console.warn('StarryPass: WASM provider unavailable; using noble-hashes.');
            }
            zeroize(tagK);

            // 2. RFC 5869 TC1 HMAC/SHA-256 KAT (first 8 bytes of PRK).
            const tcSalt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            const tcIkm = new Uint8Array(22).fill(0x0b);
            const prk = await hmacSha256(tcSalt, tcIkm);
            const expectedPrk8 = [0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf];
            for (let j = 0; j < 8; j++) {
                if (prk[j] !== expectedPrk8[j]) throw new Error('KAT_SHA256_FAILED');
            }
            zeroize(prk);
        })().catch((err) => {
            wasmProviderEnabled = false;
            selfTestPromise = null; // allow retry on transient failure
            throw err;
        });
    }
    return selfTestPromise;
}

async function argon2idDeriveWithKey(password, salt, key, ad, inWorker) {
    const opts = {
        t: 3, m: 32, p: 4, dkLen: 32, version: 0x13,
        key, personalization: ad,
    };
    const pending = inWorker
        ? Promise.resolve(argon2id(password, salt, opts))
        : argon2idAsync(password, salt, { ...opts, asyncTick: 30 });
    return Promise.resolve(pending).then(validateSessionKey);
}

/* ------------------------------------------------------------------ *
 * Input canonicalisation (verbatim from v2)                           *
 * ------------------------------------------------------------------ */

function canonicalizeInputs(req) {
    const masterNorm = String(req.master || '').normalize('NFC');
    const codeNorm   = String(req.code || '').trim().normalize('NFC');
    // Keep the production golden-set fallback contract; never select a
    // prototype property such as constructor/__proto__ as a mode or tier.
    const tierSpec = Object.prototype.hasOwnProperty.call(TIERS, req.tier) ? TIERS[req.tier] : TIERS.standard;
    const counter = Math.max(1, Math.min(9999, parseInt(req.counter, 10) || 1));
    const length  = Math.max(4, Math.min(64, parseInt(req.length, 10) || 16));
    const mode = Object.prototype.hasOwnProperty.call(MODES, req.mode) ? req.mode : 'full';
    let masterBytes, codeBytes;
    try {
        masterBytes = encoder.encode(masterNorm);
        codeBytes = encoder.encode(codeNorm);
        return { masterBytes, codeBytes, tierSpec, counter, length, mode };
    } catch (err) {
        zeroize(masterBytes);
        zeroize(codeBytes);
        throw err;
    }
}

/* ------------------------------------------------------------------ *
 * Engine                                                              *
 * ------------------------------------------------------------------ */

export function spv2CoreFactory(workerGlobal, _forcePureJs) {
    const inWorker = !!(workerGlobal && typeof workerGlobal.postMessage === 'function');

    let cachedTag = null;
    let cachedSk = null;
    let sessionNonce = null;       // private to this engine, like its cache
    let generation = 0;
    let queue = Promise.resolve(); // serialises derive/wipe (async safety)

    function getSessionNonce() {
        if (!sessionNonce) {
            const candidate = new Uint8Array(32);
            try {
                // Preserve production's mandatory CSPRNG policy. Publish only
                // after success: an exception must never leave a zero/partial key.
                globalThis.crypto.getRandomValues(candidate);
                sessionNonce = candidate;
            } catch (err) {
                zeroize(candidate);
                throw new Error('RNG_UNAVAILABLE');
            }
        }
        return sessionNonce;
    }

    function wipeSession() {
        zeroize(cachedTag); cachedTag = null;
        zeroize(cachedSk); cachedSk = null;
        zeroize(sessionNonce); sessionNonce = null;
    }

    function assertCurrent(epoch) {
        if (epoch !== generation) throw new Error('SESSION_WIPED');
    }

    async function deriveOnce(req, epoch, inputError) {
        let inp, reqTag, salt, sk;
        let usedCache = false, completed = false;
        try {
            assertCurrent(epoch);
            await runSelfTest(inWorker);
            assertCurrent(epoch);
            if (inputError) throw inputError.error;
            inp = canonicalizeInputs(req);
            if (!inp.masterBytes.length || !inp.codeBytes.length) throw new Error('EMPTY_INPUT');
            reqTag = await computeSessionTag(inp.masterBytes, inp.codeBytes, inp.tierSpec.id, getSessionNonce());
            assertCurrent(epoch);
            if (cachedTag && cachedSk && constantTimeEqual(reqTag, cachedTag)) {
                sk = cachedSk;
                usedCache = true;
            } else {
                salt = await buildSalt(inp.codeBytes, inp.tierSpec.id);
                assertCurrent(epoch);
                sk = await argon2idDerive({
                    password: inp.masterBytes, salt, ad: DOMAIN_AD,
                    memoryKiB: inp.tierSpec.memoryKiB, passes: inp.tierSpec.passes,
                    parallelism: inp.tierSpec.parallelism, tagLength: 32,
                }, inWorker);
                assertCurrent(epoch);
            }
            zeroize(inp.masterBytes);
            const pwd = await synthesizePassword(sk, inp.codeBytes, inp.counter, inp.length, inp.mode);
            assertCurrent(epoch);
            // A failed/stale derivation must not publish key material to cache.
            if (!usedCache) {
                zeroize(cachedTag);
                zeroize(cachedSk);
                cachedTag = reqTag; reqTag = null;
                cachedSk = sk;
            }
            completed = true;
            return { password: pwd, cached: usedCache };
        } finally {
            if (inp) { zeroize(inp.masterBytes); zeroize(inp.codeBytes); }
            zeroize(reqTag);
            zeroize(salt);
            if (sk && sk !== cachedSk) zeroize(sk);
            if (!completed) wipeSession();
        }
    }

    /* All operations run through one queue so a wipe can never zeroise
     * key material that a concurrently running derive still holds. */
    function enqueue(fn) {
        const run = queue.then(fn, fn);
        queue = run.then(() => undefined, () => undefined);
        return run;
    }

    const api = {
        derive: (req) => {
            const epoch = generation;
            let snapshot, inputError;
            try {
                // Capture the six request fields now, not after an async KAT
                // or earlier queued job. Reusing a caller's request object
                // must not silently change a previously requested password.
                snapshot = { master: req.master, code: req.code, tier: req.tier,
                    counter: req.counter, length: req.length, mode: req.mode };
            } catch (error) {
                inputError = { error }; // preserve Promise/FIFO and error cleanup
            }
            return enqueue(() => deriveOnce(snapshot, epoch, inputError));
        },
        wipeSession: () => {
            generation++; // immediately invalidate active and already queued work
            return enqueue(async () => { wipeSession(); });
        },
        /* Which Argon2id provider won the boot cross-KAT (diagnostics). */
        provider: () => (wasmProviderEnabled ? 'hash-wasm' : 'noble-hashes'),
    };

    if (inWorker) {
        workerGlobal.onmessage = function (ev) {
            const data = ev.data || {};
            const id = data.id;
            if (data.type === 'wipe') {
                // Reply only after the actual queued wipe has completed.
                api.wipeSession().then(() => {
                    workerGlobal.postMessage({ id, type: 'wiped' });
                });
                return;
            }
            if (data.type === 'derive') {
                api.derive(data).then((res) => {
                    workerGlobal.postMessage({ id, ok: true, password: res.password, cached: res.cached });
                }, (err) => {
                    workerGlobal.postMessage({
                        id, ok: false,
                        error: err && err.message ? err.message : 'DERIVE_ERROR',
                    });
                });
            }
        };
    }

    return api;
}

/* Expose the factory exactly like the original core: on `self` when one
 * exists (browser window / worker), otherwise on globalThis (Node tests). */
const rootRef = typeof self !== 'undefined' ? self : globalThis;
rootRef.spv2CoreFactory = spv2CoreFactory;

/* Classic worker auto-attach: spv2-worker.js just importScripts() this
 * file, and the original registered onmessage at evaluation time. */
if (typeof WorkerGlobalScope !== 'undefined' && rootRef instanceof WorkerGlobalScope) {
    spv2CoreFactory(rootRef, false);
}
