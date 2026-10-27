# Vendored build provenance

`argon2.umd.min.cjs` is the rollup build of **hash-wasm@4.12.0** plus the
pending upstream patch adding the Argon2 `ad` (associated data) option
required by the StarryPass v2 H0 framing.

- Upstream: https://github.com/Daninet/hash-wasm
- Fork + patch branch: https://github.com/lingyicute/hash-wasm/tree/feat/argon2-associated-data
  (commit `83879b1` — PR opened upstream, awaiting review; upstream
  maintainer has been inactive, so the fork is vendored meanwhile)
- Built from the patched source with the project's own `rollup -c`.
  The WASM binary inside is byte-identical to the published
  `hash-wasm@4.12.0` npm package (SHA-verified during extraction) —
  the patch is TypeScript-only and never touches the binary.
- License: MIT (see LICENSE in this directory).
- Verification: `npm run test:parity` proves byte-identical Argon2id
  output vs @noble/hashes on production parameters, and the runtime
  self-test cross-checks both providers against the RFC 9106 §5.3
  vector on every session start (mismatch disables the WASM path).
