// Node scrypt provider for vault-core.
//
// Uses the platform's native scryptSync — no new dependency. Verified to
// produce byte-identical output to the browser's hash-wasm build for the same
// (password, salt, N, r, p), including non-ASCII passphrases, which is what
// lets a vault written by the CLI be opened on the phone and vice versa.

import { scryptSync } from 'node:crypto';
import { setScryptProvider } from './vault-core.js';

// 128 * N * r bytes plus overhead. N=2^16, r=8 needs 64 MB; give headroom so
// raising the cost factor later doesn't fail with an opaque maxmem error.
const MAXMEM = 512 * 1024 * 1024;

export function nodeScrypt(password, salt, { N, r, p, dkLen }) {
  return new Uint8Array(scryptSync(password, salt, dkLen, { N, r, p, maxmem: MAXMEM }));
}

export function installNodeScrypt() {
  setScryptProvider(nodeScrypt);
}

installNodeScrypt();
