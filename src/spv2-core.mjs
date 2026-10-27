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
 * Everything else (canonicalisation, salt framing, HKDF stream layout,
 * zero-bias rejection synthesis, session cache) is *specification logic*
 * ported verbatim from the original spv2-core.js so that every existing
 * user derives byte-identical passwords. The contract is enforced by
 * tests/vectors.json (original vectors) and tests/golden.json (golden set
 * generated with the original implementation).
 *
 * Copyright (C) 2024-2026 lingyicute — AGPL-3.0 (same as StarryPass).
 */

import { argon2id, argon2idAsync } from '@noble/hashes/argon2.js';

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

/**
 * Argon2id v1.3 via @noble/hashes.
 * `secret` is intentionally never set (v2 uses an empty secret);
 * `ad` carries the domain-separation string exactly as the original did.
 * In a dedicated worker we run the synchronous variant (the worker is
 * already off the UI thread); everywhere else we run the async variant
 * which yields periodically so the page stays responsive.
 */
function argon2idDerive({ password, salt, ad, memoryKiB, passes, parallelism, tagLength }, inWorker) {
    const opts = {
        t: passes,
        m: memoryKiB,
        p: parallelism,
        dkLen: tagLength,
        version: 0x13,
        personalization: ad,
    };
    return inWorker
        ? Promise.resolve(argon2id(password, salt, opts))
        : argon2idAsync(password, salt, { ...opts, asyncTick: 30 });
}

/* ------------------------------------------------------------------ *
 * Stage 1 — salt                                                      *
 * ------------------------------------------------------------------ */

async function buildSalt(codeBytes, tierId) {
    const tierByte = new Uint8Array([tierId]);
    const saltIn = concatBytes([DOMAIN_SALT, lenPrefixed(codeBytes), tierByte]);
    const s = await sha256(saltIn);
    zeroize(saltIn);
    return s;
}

/* ------------------------------------------------------------------ *
 * Stage 2 — session cache (same HMAC-over-random-nonce tag as v2)     *
 * ------------------------------------------------------------------ */

let sessionNonce = null;

function getSessionNonce() {
    if (!sessionNonce) {
        sessionNonce = new Uint8Array(32);
        globalThis.crypto.getRandomValues(sessionNonce);
    }
    return sessionNonce;
}

async function computeSessionTag(masterBytes, codeBytes, tierId) {
    const tierByte = new Uint8Array([tierId]);
    const msg = concatBytes([DOMAIN_CACHE, lenPrefixed(masterBytes), lenPrefixed(codeBytes), tierByte]);
    const mac = await hmacSha256(getSessionNonce(), msg);
    zeroize(msg);
    return mac;
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
            // Keep only the most recent 32-byte block (T(blockIdx)).
            this.buf = new Uint8Array(bits).slice(-32);
            this.pos = 0;
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
    const info = concatBytes([DOMAIN_EXPAND, meta, lenPrefixed(codeBytes)]);

    const stream = new HkdfStream(info);
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

    zeroize(info);
    stream.dispose();
    return result;
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
    return inWorker
        ? Promise.resolve(argon2id(password, salt, opts))
        : argon2idAsync(password, salt, { ...opts, asyncTick: 30 });
}

/* ------------------------------------------------------------------ *
 * Input canonicalisation (verbatim from v2)                           *
 * ------------------------------------------------------------------ */

function canonicalizeInputs(req) {
    const masterNorm = String(req.master || '').normalize('NFC');
    const codeNorm   = String(req.code || '').trim().normalize('NFC');
    const masterBytes = encoder.encode(masterNorm);
    const codeBytes   = encoder.encode(codeNorm);
    const tierSpec = TIERS[req.tier] || TIERS.standard;
    const counter = Math.max(1, Math.min(9999, parseInt(req.counter, 10) || 1));
    const length  = Math.max(4, Math.min(64, parseInt(req.length, 10) || 16));
    const mode    = MODES[req.mode] ? req.mode : 'full';
    return { masterBytes, codeBytes, tierSpec, counter, length, mode };
}

/* ------------------------------------------------------------------ *
 * Engine                                                              *
 * ------------------------------------------------------------------ */

export function spv2CoreFactory(workerGlobal, _forcePureJs) {
    const inWorker = !!(workerGlobal && typeof workerGlobal.postMessage === 'function');

    let cachedTag = null;
    let cachedSk  = null;
    let queue = Promise.resolve();   // serialises derive/wipe (async safety)

    function wipeSession() {
        if (cachedTag) { zeroize(cachedTag); cachedTag = null; }
        if (cachedSk)  { zeroize(cachedSk);  cachedSk  = null; }
        if (sessionNonce) { zeroize(sessionNonce); sessionNonce = null; }
    }

    async function deriveOnce(req) {
        await runSelfTest(inWorker);

        const inp = canonicalizeInputs(req);
        if (!inp.masterBytes.length || !inp.codeBytes.length) {
            zeroize(inp.masterBytes);
            zeroize(inp.codeBytes);
            throw new Error('EMPTY_INPUT');
        }

        const reqTag = await computeSessionTag(inp.masterBytes, inp.codeBytes, inp.tierSpec.id);

        let sk = null;
        let usedCache = false;
        if (cachedTag && cachedSk && constantTimeEqual(reqTag, cachedTag)) {
            sk = cachedSk;
            usedCache = true;
            zeroize(reqTag);
        } else {
            const salt = await buildSalt(inp.codeBytes, inp.tierSpec.id);
            const fresh = await argon2idDerive({
                password: inp.masterBytes,
                salt,
                ad: DOMAIN_AD,
                memoryKiB: inp.tierSpec.memoryKiB,
                passes: inp.tierSpec.passes,
                parallelism: inp.tierSpec.parallelism,
                tagLength: 32,
            }, inWorker);
            zeroize(salt);
            if (cachedTag) zeroize(cachedTag);
            if (cachedSk) zeroize(cachedSk);
            cachedSk = fresh;
            cachedTag = reqTag;
            sk = fresh;
        }

        zeroize(inp.masterBytes);
        const pwd = await synthesizePassword(sk, inp.codeBytes, inp.counter, inp.length, inp.mode);
        zeroize(inp.codeBytes);
        return { password: pwd, cached: usedCache };
    }

    /* All operations run through one queue so a wipe can never zeroise
     * key material that a concurrently running derive still holds. */
    function enqueue(fn) {
        const run = queue.then(fn, fn);
        queue = run.then(() => undefined, () => undefined);
        return run;
    }

    const api = {
        derive: (req) => enqueue(() => deriveOnce(req)),
        wipeSession: () => { enqueue(async () => { wipeSession(); }) ; },
    };

    if (inWorker) {
        workerGlobal.onmessage = function (ev) {
            const data = ev.data || {};
            if (data.type === 'wipe') {
                api.wipeSession();
                // Reply only after the queued wipe actually ran, so the
                // pagehide handshake keeps the original semantics.
                enqueue(async () => {}).then(() => {
                    workerGlobal.postMessage({ id: data.id, type: 'wiped' });
                });
                return;
            }
            if (data.type === 'derive') {
                api.derive(data).then((res) => {
                    workerGlobal.postMessage({ id: data.id, ok: true, password: res.password, cached: res.cached });
                }, (err) => {
                    workerGlobal.postMessage({
                        id: data.id, ok: false,
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
