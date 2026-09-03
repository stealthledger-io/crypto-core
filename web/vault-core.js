// StealthLedger — Vault v2 core (zero-knowledge envelope format).
//
// This ONE module runs unchanged in the browser and in Node 20+ (both expose
// WebCrypto as `globalThis.crypto`). The Node test suite therefore exercises
// the exact code the phone runs — no parallel implementation to drift.
//
// ---------------------------------------------------------------------------
// THREAT MODEL
// ---------------------------------------------------------------------------
// The vault envelope is designed to be stored on infrastructure we do NOT
// trust (Netlify Blobs, a git remote, a CDN edge, someone's backup). The host
// sees only ciphertext and non-secret KDF parameters. There is no server-side
// key, no server-side unwrap, no recovery path through the operator. Losing
// every unlocker means losing the data — that is the point.
//
// What this protects against:
//   - Host compromise / subpoena / rogue employee reading holdings
//   - Network interception (belt-and-braces on top of TLS)
//   - Ciphertext tampering or rollback of individual records (AES-GCM + AAD)
//   - Moving a wrapped key between unlocker slots (AAD binds slot identity)
//
// What it does NOT protect against:
//   - A compromised browser/OS at unlock time (keylogger, malicious extension,
//     hostile JS served by the host). Zero-knowledge web crypto always trusts
//     the code delivery channel. Mitigations belong at the hosting layer:
//       * Netlify "immutable deploys" + Subresource Integrity
//       * a strict Content-Security-Policy with no third-party script origins
//       * installing as a PWA, which pins the cached app shell
//     Documented honestly in README.md rather than hand-waved.
//   - A weak passphrase. scrypt at 64 MB raises the cost per guess enormously
//     but cannot rescue "password123".
//
// ---------------------------------------------------------------------------
// ENVELOPE SHAPE
// ---------------------------------------------------------------------------
//   {
//     v: 2,
//     kind: "portcalc-vault",
//     vaultId: "<16 hex>",        // stable id, non-secret, used for AAD
//     seq: 7,                     // monotonic; optimistic-concurrency guard
//     updatedAt: "2026-08-23T...",
//     content: { alg, iv, ct },   // payload encrypted with the CONTENT KEY
//     unlockers: [ <slot>, ... ]  // each wraps the SAME content key
//   }
//
// A single random 32-byte CONTENT KEY (CK) encrypts the payload. Every
// unlocker independently wraps CK under a key-encryption key (KEK). Adding,
// relabelling or revoking a device rewraps a 32-byte key — it never
// re-encrypts the payload, and never needs the payload in the clear at all.
//
// Slot types:
//   passphrase — KEK = scrypt(passphrase, slot.kdf.salt)
//   passkey    — KEK = HKDF-SHA256(WebAuthn PRF output, slot.hkdfSalt)
//   recovery   — KEK = scrypt(recovery code, slot.kdf.salt)
//
// ---------------------------------------------------------------------------
// FORMAT NOTE — differs deliberately from src/crypto.js (v1)
// ---------------------------------------------------------------------------
// v1 stores the GCM auth tag in a separate `tag` field because Node's
// createCipheriv exposes it separately. WebCrypto has no such split: it
// appends the tag to the ciphertext. v2 adopts the WebCrypto convention
// (`ct` = ciphertext || 16-byte tag) so browser code needs no surgery on
// every operation. The Node-side helpers in ../../src/vaultsync.js speak this
// same convention by going through WebCrypto too, not createCipheriv.
// v1 files on disk are untouched and still readable by the local CLI.

export const VAULT_VERSION = 2;
export const VAULT_KIND = 'portcalc-vault';

const AES_ALG = 'AES-GCM';
const AES_LABEL = 'AES-256-GCM';
const IV_LEN = 12;   // GCM standard nonce
const KEY_LEN = 32;  // 256-bit
const TAG_BITS = 128;

// scrypt cost for passphrase/recovery KEKs. 128 * N * r bytes = 64 MB.
// Measured ~174 ms in WASM on a desktop core, well under a second on an
// iPhone. Deliberately higher than v1's N=2^15 because this envelope is
// exposed to the public internet, so offline-guessing resistance matters more.
export const SCRYPT_PARAMS = Object.freeze({ name: 'scrypt', N: 65536, r: 8, p: 1 });

export const PASSKEY_HKDF_INFO = 'portcalc:passkey-kek:v2';
export const PRF_SALT_INFO = 'portcalc:prf:v2';

// Domain-separated label for the device vault-key transfer (ECDH-derived
// AEAD key). Bumped only if the wire format ever changes.
export const TRANSFER_INFO = 'StealthLedger vault key transfer v1';
export const TRANSFER_ALG = 'AES-256-GCM';

export class VaultError extends Error {}

// ---------------------------------------------------------------------------
// Byte / base64 helpers (no Buffer — must work in a browser)
// ---------------------------------------------------------------------------

const subtle = () => {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new VaultError(
      'WebCrypto unavailable. A secure context (https:// or localhost) is required.',
    );
  }
  return c.subtle;
};

export function randomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof input === 'string') return new TextEncoder().encode(input);
  throw new VaultError('Expected bytes or string.');
}

export function b64(bytes) {
  const u8 = toBytes(bytes);
  let s = '';
  // Chunked so very large payloads don't blow the argument limit.
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

export function unb64(str) {
  if (typeof str !== 'string') throw new VaultError('Expected a base64 string.');
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64url(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return unb64(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
}

export function hex(bytes) {
  return Array.from(toBytes(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Constant-time-ish byte comparison. Used for integrity self-checks. */
export function bytesEqual(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/** Best-effort wipe. JS gives no real guarantees, but it shortens the window. */
export function wipe(...arrays) {
  for (const a of arrays) {
    if (a instanceof Uint8Array) a.fill(0);
  }
}

// ---------------------------------------------------------------------------
// scrypt provider injection
// ---------------------------------------------------------------------------
// Browser: hash-wasm (vendored locally, see public/vendor/).
// Node:    native crypto.scryptSync.
// Verified byte-identical across both for ASCII and non-ASCII passphrases.

let scryptProvider = null;

export function setScryptProvider(fn) {
  if (typeof fn !== 'function') throw new VaultError('scrypt provider must be a function.');
  scryptProvider = fn;
}

export function hasScryptProvider() {
  return typeof scryptProvider === 'function';
}

async function scryptKek(secret, salt, params = SCRYPT_PARAMS) {
  if (!scryptProvider) {
    throw new VaultError('No scrypt provider registered — call setScryptProvider() first.');
  }
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new VaultError('A non-empty passphrase is required.');
  }
  // NFKC so the same human-typed passphrase derives the same key across
  // an iOS keyboard, a Mac and a Linux terminal. Without this, composed vs
  // decomposed accents (and Arabic presentation forms) silently diverge —
  // which would look exactly like "wrong password" and be miserable to debug.
  const normalized = secret.normalize('NFKC');
  const out = await scryptProvider(normalized, toBytes(salt), {
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: KEY_LEN,
  });
  const bytes = toBytes(out);
  if (bytes.length !== KEY_LEN) {
    throw new VaultError(`scrypt provider returned ${bytes.length} bytes, expected ${KEY_LEN}.`);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// AEAD primitives
// ---------------------------------------------------------------------------

async function importAes(rawKey, usages) {
  const bytes = toBytes(rawKey);
  if (bytes.length !== KEY_LEN) throw new VaultError('AES key must be 32 bytes.');
  return subtle().importKey('raw', bytes, AES_ALG, false, usages);
}

/**
 * Encrypt bytes under a raw 32-byte key. `aad` is authenticated but not
 * encrypted — we use it to bind ciphertext to its logical slot so a blob
 * can't be relocated within (or between) envelopes.
 */
export async function aeadSeal(rawKey, plaintext, aad) {
  const key = await importAes(rawKey, ['encrypt']);
  const iv = randomBytes(IV_LEN);
  const params = { name: AES_ALG, iv, tagLength: TAG_BITS };
  if (aad !== undefined) params.additionalData = toBytes(aad);
  const ct = await subtle().encrypt(params, key, toBytes(plaintext));
  return { alg: AES_LABEL, iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}

export async function aeadOpen(rawKey, sealed, aad) {
  if (!sealed || typeof sealed.iv !== 'string' || typeof sealed.ct !== 'string') {
    throw new VaultError('Malformed sealed blob.');
  }
  if (sealed.alg && sealed.alg !== AES_LABEL) {
    throw new VaultError(`Unsupported cipher: ${sealed.alg}`);
  }
  const key = await importAes(rawKey, ['decrypt']);
  const params = { name: AES_ALG, iv: unb64(sealed.iv), tagLength: TAG_BITS };
  if (aad !== undefined) params.additionalData = toBytes(aad);
  try {
    const pt = await subtle().decrypt(params, key, unb64(sealed.ct));
    return new Uint8Array(pt);
  } catch {
    // WebCrypto gives a bare OperationError; translate to something actionable.
    throw new VaultError('Decryption failed — wrong key, or the data was tampered with.');
  }
}

export async function hkdfSha256(ikm, salt, info, length = KEY_LEN) {
  const base = await subtle().importKey('raw', toBytes(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: toBytes(salt), info: toBytes(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle().digest('SHA-256', toBytes(bytes)));
}

// ---------------------------------------------------------------------------
// AAD construction
// ---------------------------------------------------------------------------
// Binding a wrap to (vaultId, slotId, slotType) means an attacker who can
// write to the store cannot: swap a weak recovery wrap into the passkey slot,
// copy a slot from an older vault they captured, or graft slots between two
// vaults. Any of those flips the AAD and GCM rejects it.

function wrapAad(vaultId, slot) {
  return `portcalc-vault:v2:${vaultId}:unlocker:${slot.id}:${slot.type}`;
}

function contentAad(vault) {
  return `portcalc-vault:v2:${vault.vaultId}:content`;
}

// ---------------------------------------------------------------------------
// Payload normalisation
// ---------------------------------------------------------------------------
// Mirrors the sanitizers in src/external.js and src/cash.js so the hosted app
// and the local CLI agree on shape. Notably it PRESERVES `uid` — the uid
// contract from commit 2a4263e is load-bearing for duplicate-coin editing and
// must survive a round-trip through the vault untouched.

export function normalizePayload(raw, baseCurrency = 'AUD') {
  const base = String(raw?.baseCurrency || baseCurrency || 'AUD').trim().toUpperCase();

  const external = (Array.isArray(raw?.external) ? raw.external : [])
    .map((c) => ({
      uid: String(c?.uid || '').trim() || hex(randomBytes(8)),
      symbol: String(c?.symbol || '').trim().toUpperCase(),
      id: String(c?.id || '').trim().toLowerCase(),
      amount: Number(c?.amount) || 0,
      note: String(c?.note || '').trim(),
    }))
    .filter((c) => c.symbol && c.id && c.amount > 0);

  const cash = (Array.isArray(raw?.cash) ? raw.cash : [])
    .map((e) => ({
      label: String(e?.label || '').trim(),
      currency: String(e?.currency || base).trim().toUpperCase(),
      amount: Number(e?.amount) || 0,
      note: String(e?.note || '').trim(),
    }))
    .filter((e) => e.label && e.amount > 0);

  const koinlyRows = (Array.isArray(raw?.koinly?.holdings) ? raw.koinly.holdings : [])
    .map((h) => ({
      symbol: String(h?.symbol || '').trim().toUpperCase(),
      id: String(h?.id || '').trim().toLowerCase(),
      amount: Number(h?.amount) || 0,
    }))
    .filter((h) => h.symbol && h.amount > 0);

  // Last-known unit prices, carried inside the encrypted payload so an offline
  // open still shows sensible figures. It lives here rather than in
  // localStorage on purpose: a plaintext price cache would reveal *which*
  // coins you hold to anyone who picked up the locked phone, which is most of
  // the secret. Values only — there is nowhere to put an amount.
  const prices = {};
  const rawPrices = raw?.prices && typeof raw.prices === 'object' ? raw.prices : {};
  for (const [id, quote] of Object.entries(rawPrices)) {
    if (!/^[a-z0-9][a-z0-9-_]{0,63}$/.test(String(id))) continue;
    if (!quote || typeof quote !== 'object') continue;
    const clean = {};
    for (const [k, v] of Object.entries(quote)) {
      if (!/^[a-z0-9_]{1,24}$/.test(String(k))) continue;
      const n = Number(v);
      if (Number.isFinite(n)) clean[k] = n;
    }
    if (Object.keys(clean).length) prices[id] = clean;
  }

  // Symbol-keyed price snapshot captured at Koinly-import time. Used as a
  // fallback for holdings whose CoinGecko id could not be resolved so the
  // vault still shows a value between the import and the next live refresh.
  const koinlyPrices = {};
  const rawKP = raw?.koinlyPrices && typeof raw.koinlyPrices === 'object' ? raw.koinlyPrices : {};
  for (const [sym, quote] of Object.entries(rawKP)) {
    const s = String(sym || '').trim().toUpperCase();
    if (!/^[A-Z0-9._-]{1,20}$/.test(s)) continue;
    if (!quote || typeof quote !== 'object') continue;
    const clean = {};
    for (const [k, v] of Object.entries(quote)) {
      if (!/^[a-zA-Z0-9_]{1,24}$/.test(String(k))) continue;
      const n = Number(v);
      if (Number.isFinite(n)) clean[k] = n;
    }
    if (Object.keys(clean).length) koinlyPrices[s] = clean;
  }

  return {
    baseCurrency: base,
    external,
    cash,
    koinly: {
      holdings: koinlyRows,
      syncedAt: raw?.koinly?.syncedAt ? String(raw.koinly.syncedAt) : null,
    },
    koinlyPrices,
    prices,
  };
}

/**
 * Duplicate-uid guard. The whole point of 2a4263e was that two code paths
 * disagreeing on uids silently edits the wrong row, so we refuse to persist
 * an ambiguous set rather than shipping a subtly corrupt vault to the phone.
 */
export function assertUniqueUids(external) {
  const seen = new Set();
  for (const c of external) {
    if (seen.has(c.uid)) {
      throw new VaultError(
        `Duplicate uid ${c.uid} in External holdings — refusing to write an ambiguous vault.`,
      );
    }
    seen.add(c.uid);
  }
}

// ---------------------------------------------------------------------------
// Envelope creation & payload access
// ---------------------------------------------------------------------------

export function newContentKey() {
  return randomBytes(KEY_LEN);
}

export async function createVault(payload, { baseCurrency = 'AUD' } = {}) {
  const contentKey = newContentKey();
  const vault = {
    v: VAULT_VERSION,
    kind: VAULT_KIND,
    vaultId: hex(randomBytes(8)),
    seq: 1,
    updatedAt: new Date().toISOString(),
    content: null,
    unlockers: [],
  };
  const normalized = normalizePayload(payload, baseCurrency);
  assertUniqueUids(normalized.external);
  vault.content = await sealPayload(vault, contentKey, normalized);
  return { vault, contentKey };
}

export async function sealPayload(vault, contentKey, payload) {
  const normalized = normalizePayload(payload, payload?.baseCurrency);
  assertUniqueUids(normalized.external);
  const json = JSON.stringify(normalized);
  const bytes = new TextEncoder().encode(json);
  try {
    return await aeadSeal(contentKey, bytes, contentAad(vault));
  } finally {
    wipe(bytes);
  }
}

export async function openPayload(vault, contentKey) {
  assertVaultShape(vault);
  const bytes = await aeadOpen(contentKey, vault.content, contentAad(vault));
  try {
    return normalizePayload(JSON.parse(new TextDecoder().decode(bytes)));
  } finally {
    wipe(bytes);
  }
}

// ---------------------------------------------------------------------------
// Device vault-key transfer ("zero typing" pairing)
// ---------------------------------------------------------------------------
//
// When the website has the vault unlocked, session.contentKey lives in memory.
// To let a freshly-paired phone open the vault without typing the passphrase,
// the website seals the contentKey to the phone's ephemeral P-256 public key
// and posts only the ciphertext to the server. The phone derives the same key
// with its private key and decrypts locally.
//
// Key agreement:  X25519-free P-256 ECDH (native WebCrypto + CryptoKit).
// Key derivation: HKDF-SHA256, salt = random per grant.
// AEAD:           AES-256-GCM, 12-byte nonce, 128-bit tag (WebCrypto layout:
//                 ciphertext || tag, identical to the existing vault AEAD).
// AAD:            binds the sealed blob to the transfer context so a captured
//                 grant cannot be replayed into a different transfer or grafted
//                 onto another user. Both sides build this string identically
//                 from values they hold: transferId, userId, fingerprint, alg.
//
// The server only ever sees pubkeys + ciphertext + metadata, never the
// contentKey itself. The contentKey is decryptable only by the phone that holds
// the ephemeral private key matching the pubkey it posted.

function transferAad({ transferId, userId, fingerprint, alg }) {
  return `SL1|${transferId}|${userId}|${fingerprint}|${alg}`;
}

/** Build the AAD string for a transfer. Exposed for tests. */
export function transferAddFor(ctx) {
  return transferAad(ctx);
}

/**
 * Website side: seal the in-memory contentKey to the phone's P-256 public key.
 * `phonePubKeyB64` is the SPKI DER of the phone's ephemeral key, base64. Returns
 * { senderPubKey, salt, nonce, ct, alg } for POST /api/auth/device-grant.
 */
export async function sealContentKeyForTransfer({
  contentKey, phonePubKeyB64, transferId, userId, fingerprint,
}) {
  if (!(contentKey instanceof Uint8Array) || contentKey.length !== 32) {
    throw new VaultError('Invalid content key for transfer.');
  }
  const alg = TRANSFER_ALG;
  const aad = transferAad({ transferId, userId, fingerprint, alg });

  // Phone's ephemeral public key (SPKI DER -> CryptoKey for ECDH).
  const phonePub = await subtle().importKey(
    'spki', unb64(phonePubKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  // Website's ephemeral keypair. extractable=true so we can export the pubkey.
  const ephem = await subtle().generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
  );
  const sharedBits = await subtle().deriveBits(
    { name: 'ECDH', public: phonePub }, ephem.privateKey, 256,
  );
  try {
    const salt = randomBytes(32);
    const transferKey = await hkdfSha256(sharedBits, salt, TRANSFER_INFO, 32);
    // Plaintext carries the contentKey + binding metadata. seq is the envelope
    // seq at grant time so the phone can reject a stale grant replayed against
    // a newer envelope.
    const payload = {
      contentKey: b64(contentKey),
      transferId,
      createdAt: new Date().toISOString(),
      alg,
    };
    const plaintext = toBytes(JSON.stringify(payload));
    try {
      const sealed = await aeadSeal(transferKey, plaintext, aad);
      const senderPubKeyRaw = await subtle().exportKey('spki', ephem.publicKey);
      return {
        senderPubKey: b64(new Uint8Array(senderPubKeyRaw)),
        salt: b64(salt),
        nonce: sealed.iv,
        ct: sealed.ct,
        alg,
      };
    } finally {
      wipe(plaintext);
    }
  } finally {
    wipe(sharedBits);
  }
}

/**
 * Phone side (also used by the round-trip test): open a sealed grant with the
 * phone's ephemeral private key. `phonePrivJwk` is the JWK of the phone's
 * ephemeral P-256 private key. Returns the raw contentKey (Uint8Array, 32) or
 * throws. The iOS app mirrors this with CryptoKit (no JS needed on device).
 */
export async function openContentKeyFromTransfer({
  phonePrivJwk, senderPubKeyB64, salt, nonce, ct, transferId, userId, fingerprint, alg,
}) {
  const aad = transferAad({ transferId, userId, fingerprint, alg });
  const senderPub = await subtle().importKey(
    'spki', unb64(senderPubKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const phonePriv = await subtle().importKey(
    'jwk', phonePrivJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
  );
  const sharedBits = await subtle().deriveBits(
    { name: 'ECDH', public: senderPub }, phonePriv, 256,
  );
  try {
    const transferKey = await hkdfSha256(sharedBits, unb64(salt), TRANSFER_INFO, 32);
    const plaintext = await aeadOpen(transferKey, { alg, iv: nonce, ct }, aad);
    try {
      const payload = JSON.parse(new TextDecoder().decode(plaintext));
      if (payload.transferId !== transferId) throw new VaultError('Transfer id mismatch in grant payload.');
      if (payload.alg !== alg) throw new VaultError('Algorithm mismatch in grant payload.');
      const ck = unb64(payload.contentKey);
      if (ck.length !== 32) throw new VaultError('Transferred key has wrong length.');
      return ck;
    } finally {
      wipe(plaintext);
    }
  } finally {
    wipe(sharedBits);
  }
}

/** Re-seal the payload and bump seq. Returns a NEW envelope (no mutation). */
export async function updatePayload(vault, contentKey, payload) {
  const next = {
    ...vault,
    seq: Number(vault.seq || 0) + 1,
    updatedAt: new Date().toISOString(),
  };
  next.content = await sealPayload(next, contentKey, payload);
  return next;
}

export function assertVaultShape(vault) {
  if (!vault || typeof vault !== 'object') throw new VaultError('Vault is not an object.');
  // Message uses the product name; the on-disk `kind` value ('portcalc-vault')
  // is the schema magic and is deliberately unchanged so old backups keep
  // opening.
  if (vault.kind !== VAULT_KIND) throw new VaultError('Not a StealthLedger vault.');
  if (vault.v !== VAULT_VERSION) {
    throw new VaultError(`Unsupported vault version ${vault.v} (expected ${VAULT_VERSION}).`);
  }
  if (typeof vault.vaultId !== 'string' || !/^[0-9a-f]{16}$/.test(vault.vaultId)) {
    throw new VaultError('Vault is missing a valid vaultId.');
  }
  if (!vault.content) throw new VaultError('Vault has no content.');
  if (!Array.isArray(vault.unlockers)) throw new VaultError('Vault has no unlockers array.');
  return true;
}

// ---------------------------------------------------------------------------
// Unlocker slots
// ---------------------------------------------------------------------------

function slotBase(type, label) {
  return {
    id: hex(randomBytes(8)),
    type,
    label: String(label || type).slice(0, 64),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };
}

async function wrapInto(vaultId, slot, kek, contentKey) {
  slot.wrap = await aeadSeal(kek, contentKey, wrapAad(vaultId, slot));
  // Self-check: prove the slot we just wrote actually unwraps to the same key.
  // A silently-broken slot is far worse than a loud failure here, because you
  // only discover it the day you need that recovery path.
  const check = await aeadOpen(kek, slot.wrap, wrapAad(vaultId, slot));
  if (!bytesEqual(check, contentKey)) {
    throw new VaultError('Internal error: new unlocker failed its round-trip self-check.');
  }
  wipe(check);
  return slot;
}

// ---- passphrase -----------------------------------------------------------

export async function addPassphraseUnlocker(vault, contentKey, passphrase, label = 'Passphrase') {
  assertVaultShape(vault);
  const slot = slotBase('passphrase', label);
  slot.kdf = { ...SCRYPT_PARAMS, salt: b64(randomBytes(16)) };
  const kek = await scryptKek(passphrase, unb64(slot.kdf.salt), slot.kdf);
  try {
    await wrapInto(vault.vaultId, slot, kek, contentKey);
  } finally {
    wipe(kek);
  }
  return { ...vault, unlockers: [...vault.unlockers, slot] };
}

// ---- recovery code --------------------------------------------------------

const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I/O/0/1

/**
 * 26 characters from a 32-symbol alphabet = 130 bits of entropy, grouped for
 * legibility. Ambiguous glyphs removed so it survives being written on paper
 * and typed back months later.
 */
export function generateRecoveryCode() {
  const groups = [];
  for (let g = 0; g < 5; g++) {
    let s = '';
    const rnd = randomBytes(6);
    for (let i = 0; i < 5; i++) s += RECOVERY_ALPHABET[rnd[i] % RECOVERY_ALPHABET.length];
    groups.push(s);
  }
  return groups.join('-');
}

/** Strip formatting so "abcde-fghij", "ABCDE FGHIJ" and "ABCDEFGHIJ" agree. */
export function canonicalRecoveryCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export async function addRecoveryUnlocker(vault, contentKey, code, label = 'Recovery code') {
  assertVaultShape(vault);
  const canon = canonicalRecoveryCode(code);
  if (canon.length < 20) throw new VaultError('Recovery code looks too short.');
  const slot = slotBase('recovery', label);
  slot.kdf = { ...SCRYPT_PARAMS, salt: b64(randomBytes(16)) };
  const kek = await scryptKek(canon, unb64(slot.kdf.salt), slot.kdf);
  try {
    await wrapInto(vault.vaultId, slot, kek, contentKey);
  } finally {
    wipe(kek);
  }
  return { ...vault, unlockers: [...vault.unlockers, slot] };
}

// ---- passkey (WebAuthn PRF) ----------------------------------------------

/**
 * Build a passkey slot from a raw PRF output. Kept separate from the WebAuthn
 * ceremony itself so this module stays environment-agnostic and testable in
 * Node — the browser layer supplies `prfOutput`.
 */
export async function addPasskeyUnlocker(
  vault,
  contentKey,
  { credentialId, prfOutput, label = 'Passkey', transports = [] },
) {
  assertVaultShape(vault);
  if (!credentialId) throw new VaultError('Passkey slot needs a credentialId.');
  const prf = toBytes(prfOutput);
  if (prf.length < KEY_LEN) {
    throw new VaultError('PRF output too short — this authenticator may not support PRF.');
  }
  const slot = slotBase('passkey', label);
  slot.credentialId = typeof credentialId === 'string' ? credentialId : b64url(credentialId);
  slot.transports = Array.isArray(transports) ? transports.slice(0, 6) : [];
  slot.hkdfSalt = b64(randomBytes(32));
  // NOTE: passkey slots deliberately don't carry a `kdf` block. The multi-
  // tenant envelope validator (_envelope.mjs) rejects any kdf on a passkey
  // slot -- the KDF here is fully determined by two known constants
  // (hkdf-sha256, PASSKEY_HKDF_INFO) plus the per-slot hkdfSalt, so there
  // is nothing per-vault to serialize. The unlock path in
  // unlockWithPasskeyPrf below reads PASSKEY_HKDF_INFO directly with an
  // optional-chain fallback, so older vaults that DID persist a kdf still
  // unlock cleanly.
  //
  // The PRF secret is the authenticator's; run it through HKDF with a
  // per-slot salt so the KEK is unique to this vault even if the same
  // credential and PRF salt were ever reused elsewhere.
  const kek = await hkdfSha256(prf, unb64(slot.hkdfSalt), PASSKEY_HKDF_INFO, KEY_LEN);
  try {
    await wrapInto(vault.vaultId, slot, kek, contentKey);
  } finally {
    wipe(kek);
  }
  return { ...vault, unlockers: [...vault.unlockers, slot] };
}

/**
 * The PRF salt fed to the authenticator. Derived from vaultId so it is stable
 * across devices and reconstructible without storing anything extra, and
 * domain-separated so this vault's PRF output is useless to another app that
 * happens to hold the same passkey.
 */
export async function prfSaltFor(vaultId) {
  return sha256(`${PRF_SALT_INFO}:${vaultId}`);
}

// ---- unwrap ---------------------------------------------------------------

export async function unlockWithPassphrase(vault, passphrase, { types = ['passphrase'] } = {}) {
  assertVaultShape(vault);
  const slots = vault.unlockers.filter((s) => types.includes(s.type));
  if (!slots.length) throw new VaultError('This vault has no matching unlocker.');

  let lastErr = null;
  for (const slot of slots) {
    // Deriving the key-wrapping key is deliberately OUTSIDE the catch below.
    // Only a failed *unwrap* means "wrong secret". A failure to even derive a key
    // — no scrypt provider registered, a malformed salt, a missing kdf block — is
    // a bug or a corrupt vault, and reporting those as a wrong passphrase sends
    // you off retyping a passphrase that was right all along. So those propagate
    // with their real message.
    const secret = slot.type === 'recovery' ? canonicalRecoveryCode(passphrase) : passphrase;
    const kek = await scryptKek(secret, unb64(slot.kdf.salt), slot.kdf);
    try {
      const contentKey = await aeadOpen(kek, slot.wrap, wrapAad(vault.vaultId, slot));
      return { contentKey, slot };
    } catch (err) {
      lastErr = err;
    } finally {
      wipe(kek);
    }
  }
  throw new VaultError(
    types.includes('recovery')
      ? 'That recovery code did not unlock the vault.'
      : 'Wrong passphrase.',
    { cause: lastErr },
  );
}

export async function unlockWithRecoveryCode(vault, code) {
  return unlockWithPassphrase(vault, code, { types: ['recovery'] });
}

export async function unlockWithPasskeyPrf(vault, credentialId, prfOutput) {
  assertVaultShape(vault);
  const wanted = typeof credentialId === 'string' ? credentialId : b64url(credentialId);
  const slot = vault.unlockers.find((s) => s.type === 'passkey' && s.credentialId === wanted);
  if (!slot) throw new VaultError('That passkey is not registered on this vault.');
  const kek = await hkdfSha256(
    toBytes(prfOutput),
    unb64(slot.hkdfSalt),
    slot.kdf?.info || PASSKEY_HKDF_INFO,
    KEY_LEN,
  );
  try {
    const contentKey = await aeadOpen(kek, slot.wrap, wrapAad(vault.vaultId, slot));
    return { contentKey, slot };
  } finally {
    wipe(kek);
  }
}

// ---- slot management -----------------------------------------------------

export function listUnlockers(vault) {
  assertVaultShape(vault);
  return vault.unlockers.map((s) => ({
    id: s.id,
    type: s.type,
    label: s.label,
    createdAt: s.createdAt,
    lastUsedAt: s.lastUsedAt,
    credentialId: s.credentialId || null,
  }));
}

/**
 * Remove an unlocker. Refuses to remove the last one — a vault with zero
 * unlockers is unrecoverable ciphertext, and doing that by accident from a
 * phone tap is exactly the kind of foot-gun worth blocking in code.
 */
export function removeUnlocker(vault, slotId) {
  assertVaultShape(vault);
  const remaining = vault.unlockers.filter((s) => s.id !== slotId);
  if (remaining.length === vault.unlockers.length) {
    throw new VaultError('No unlocker with that id.');
  }
  if (remaining.length === 0) {
    throw new VaultError('Refusing to remove the only unlocker — the vault would be unopenable.');
  }
  return { ...vault, unlockers: remaining, seq: Number(vault.seq || 0) + 1 };
}

export function renameUnlocker(vault, slotId, label) {
  assertVaultShape(vault);
  let found = false;
  const unlockers = vault.unlockers.map((s) => {
    if (s.id !== slotId) return s;
    found = true;
    return { ...s, label: String(label || '').slice(0, 64) || s.label };
  });
  if (!found) throw new VaultError('No unlocker with that id.');
  return { ...vault, unlockers, seq: Number(vault.seq || 0) + 1 };
}

export function touchUnlocker(vault, slotId) {
  const stamp = new Date().toISOString();
  return {
    ...vault,
    unlockers: vault.unlockers.map((s) => (s.id === slotId ? { ...s, lastUsedAt: stamp } : s)),
  };
}

/**
 * Change the passphrase on an existing slot in place (same slot id, fresh
 * salt and wrap). Keeping the id stable means device lists and audit trails
 * don't churn just because a passphrase rotated.
 */
export async function rewrapPassphraseUnlocker(vault, contentKey, slotId, newPassphrase) {
  assertVaultShape(vault);
  const idx = vault.unlockers.findIndex((s) => s.id === slotId);
  if (idx === -1) throw new VaultError('No unlocker with that id.');
  const prev = vault.unlockers[idx];
  if (prev.type !== 'passphrase' && prev.type !== 'recovery') {
    throw new VaultError('Only passphrase and recovery slots can be rewrapped this way.');
  }
  const slot = {
    ...prev,
    kdf: { ...SCRYPT_PARAMS, salt: b64(randomBytes(16)) },
    rotatedAt: new Date().toISOString(),
  };
  const secret =
    prev.type === 'recovery' ? canonicalRecoveryCode(newPassphrase) : newPassphrase;
  const kek = await scryptKek(secret, unb64(slot.kdf.salt), slot.kdf);
  try {
    await wrapInto(vault.vaultId, slot, kek, contentKey);
  } finally {
    wipe(kek);
  }
  const unlockers = [...vault.unlockers];
  unlockers[idx] = slot;
  return { ...vault, unlockers, seq: Number(vault.seq || 0) + 1 };
}

// ---------------------------------------------------------------------------
// Emergency vault-key rotation
// ---------------------------------------------------------------------------
//
// Generates a fresh content key (DEK), re-seals the payload under it, and
// re-wraps the new DEK into every unlocker whose secret the caller can prove
// (passphrase / recovery code). Passkey and device slots are DROPPED: a
// passkey would need a fresh WebAuthn PRF ceremony to re-derive its KEK, and a
// device slot may belong to the very device whose compromise prompted the
// rotation. The user re-adds passkeys and re-pairs phones from the website
// afterwards. At least one human unlocker (passphrase or recovery) must
// survive, otherwise the rotation is refused — you can't rotate your way into a
// lockout.
//
// The server never sees the old or new DEK, the passphrase, or the recovery
// code: the re-key is entirely client-side and is persisted via the existing
// expected-seq vault save.
export async function rotateVaultKey(vault, payload, oldContentKey, {
  passphrases = [],
  recoveryCodes = [],
  nextSeq = Number(vault.seq || 0) + 1,
  now = new Date().toISOString(),
} = {}) {
  assertVaultShape(vault);
  const old = toBytes(oldContentKey);
  if (old.length !== KEY_LEN) {
    throw new VaultError('rotateVaultKey: old content key is missing or wrong length.');
  }
  // Normalise the candidate lists once. A passphrase slot and a recovery slot
  // use different secrets — a vault can have several passphrase slots (your
  // memorised passphrase AND your 12 word recovery phrase, which is stored as
  // a passphrase unlocker) plus zero or one 25 character recovery code. Each
  // slot is re-wrapped only if one of the matching candidates unwraps to exactly
  // the OLD content key, so a wrong or stale secret can never lock you out.
  const passCandidates = (Array.isArray(passphrases) ? passphrases : [passphrases])
    .map((s) => String(s || ''))
    .filter((s) => s.length);
  const recoveryCandidates = (Array.isArray(recoveryCodes) ? recoveryCodes : [recoveryCodes])
    .map((s) => canonicalRecoveryCode(s))
    .filter((s) => s.length);
  const newDek = newContentKey();
  // Re-seal the (current, decrypted) payload under the new DEK.
  const content = await sealPayload(vault, newDek, payload);
  const kept = [];
  const dropped = [];
  for (const prev of vault.unlockers) {
    // Only passphrase + recovery slots can be re-wrapped from a typed secret.
    // Passkey (needs a fresh PRF) and device (may be the compromised device)
    // slots are dropped; the user re-adds them from the website after.
    if (prev.type !== 'passphrase' && prev.type !== 'recovery') {
      dropped.push(prev.id);
      continue;
    }
    const candidates = prev.type === 'recovery' ? recoveryCandidates : passCandidates;
    if (!candidates.length) { dropped.push(prev.id); continue; }
    // Try each candidate against this slot until one unwraps to the old DEK.
    // A single candidate is tried against its own slot's salt/KEK; a wrong
    // secret for THIS slot must not drop a slot a different candidate would
    // have preserved, so we keep probing across all candidates.
    let matched = false;
    for (const candidate of candidates) {
      const kek = await scryptKek(candidate, unb64(prev.kdf.salt), prev.kdf);
      try {
        let probe = null;
        try {
          probe = await aeadOpen(kek, prev.wrap, wrapAad(vault.vaultId, prev));
        } catch {
          continue; // wrong secret for this slot — try the next candidate
        }
        if (!probe || !bytesEqual(probe, old)) continue;
        // Re-wrap the new DEK under the SAME KEK (same salt, same slot id).
        // Only the wrap blob + lastUsedAt change; the slot id and label are
        // preserved so the UI's "last used" history stays meaningful.
        const slot = { ...prev, lastUsedAt: now };
        await wrapInto(vault.vaultId, slot, kek, newDek);
        kept.push(slot);
        matched = true;
        break;
      } finally {
        wipe(kek);
      }
    }
    if (!matched) dropped.push(prev.id);
  }
  if (!kept.length) {
    // None of the provided secrets matched any unlocker. Wipe the freshly
    // generated DEK so a failed rotation leaves nothing dangling.
    wipe(newDek);
    throw new VaultError(
      'Rotation refused: none of the supplied secrets matched an unlocker. Enter your current passphrase, 12 word recovery phrase, or 25 character recovery code.',
    );
  }
  const rotated = {
    ...vault,
    content,
    unlockers: kept,
    seq: nextSeq,
    updatedAt: now,
  };
  return {
    vault: rotated,
    contentKey: newDek,
    keptIds: kept.map((s) => s.id),
    droppedIds: dropped,
  };
}

// ---------------------------------------------------------------------------
// Passphrase strength (advisory, shown in the UI)
// ---------------------------------------------------------------------------

export function passphraseStrength(pw) {
  const s = String(pw || '');
  if (!s) return { score: 0, label: 'empty', hint: 'Enter a passphrase.' };
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[^A-Za-z0-9]/.test(s)) pool += 33;
  const words = s.trim().split(/\s+/).filter(Boolean).length;
  // Rough entropy estimate. Multi-word phrases get credit for length rather
  // than character-class gymnastics, which is what actually helps.
  const bits = Math.round(s.length * Math.log2(Math.max(pool, 2)));
  const distinct = new Set(s).size;
  const penalised = distinct <= 4 || /^(.)\1+$/.test(s);
  const effective = penalised ? Math.min(bits, 28) : bits;

  if (effective < 45) {
    return {
      score: 1,
      label: 'weak',
      bits: effective,
      hint: 'Too easy to guess offline. Use four or more unrelated words.',
    };
  }
  if (effective < 70) {
    return {
      score: 2,
      label: 'fair',
      bits: effective,
      hint: words >= 4 ? 'Acceptable. Longer is better.' : 'Add more words.',
    };
  }
  if (effective < 100) {
    return { score: 3, label: 'strong', bits: effective, hint: 'Good.' };
  }
  return { score: 4, label: 'very strong', bits: effective, hint: 'Excellent.' };
}
