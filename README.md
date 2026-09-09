# StealthLedger Crypto Core

The encryption core that protects every StealthLedger vault. This repository
is published for **transparency and independent security audit**: anyone can
read the exact cryptography that wraps their secrets and confirm there is no
backdoor, no hard-coded key, and no path that exposes vault contents without
the user's passphrase, recovery code, or live biometric.

## Now on iPhone

**StealthLedger 1.2 is live on the App Store:**
[apps.apple.com/app/stealthledger/id6807874509](https://apps.apple.com/app/stealthledger/id6807874509)

The iOS app uses the Swift core in `swift/VaultCore/` — the same source you
see in this repository. If you want to confirm what your phone is actually
running, compare the algorithm parameters (scrypt N/r/p, HKDF info/salt
derivation, AES-GCM IV length and tag length) reported by the app against
the implementations here. The on-device code is byte-for-byte the same
source published in this repo.

Web vault: [stealthledger.io](https://stealthledger.io)

## What is here

Two implementations of the same vault crypto:

- **`swift/VaultCore/`** — the iOS / macOS core (Swift). Used by the
  StealthLedger iOS app.
- **`web/vault-core.js`** + **`web/scrypt-node.js`** — the browser / Node core
  (JavaScript). Used by the StealthLedger web vault.

Both implement the same scheme:

1. A passphrase (or recovery code, or a Face ID passkey's PRF output) is
   stretched with **scrypt** into a key-encryption key (KEK).
2. The KEK is diversified per-vault with **HKDF-SHA256**.
3. The vault's content key is **AES-256-GCM** wrapped (encrypted) under that
   diversified KEK. A wrong key fails AES-GCM authentication — the wrapped
   content key cannot be unwrapped into anything usable.
4. Passkey unlock uses the device's hardware key-derivation oracle
   (the WebAuthn PRF extension): the Secure Enclave refuses to run the PRF
   without a live biometric, and the PRF output feeds step 1 above as the KEK
   material.

No secrets, tokens, API keys, or backend credentials live in this repository —
those are held in runtime environment variables on the server side and never
enter the client crypto.

## Face ID vault unlock (1.2)

Starting in 1.2, iOS users can unlock the vault with a single Face ID tap
after any successful sign-in. The mechanism is the same as passphrase unlock:
the passphrase-derived KEK is wrapped by a Keychain-stored device secret whose
release from the Secure Enclave requires a live Face ID / Touch ID
authentication. No unwrapped key is ever cached in memory across app launches,
and no plaintext leaves the device.

## What is NOT here

This is the crypto core only. It does **not** contain the app UI, the web app,
server code, the price proxy, auth, sync, or any product plumbing. Publishing
the crypto core lets the vault be audited and trusted without exposing the
product to cloning.

## Verification

If you want to confirm a vault you control was sealed by this code: compare the
algorithm parameters (scrypt N/r/p, HKDF info/salt derivation, AES-GCM IV
length and tag length) reported by your client against the implementations in
this repository. The on-device / in-browser code is byte-for-byte the same
source you see here.

## Reporting a vulnerability

If you find a security issue in this crypto core, please email
**security@stealthledger.io** rather than opening a public issue. We will
respond within 48 hours.

## License

Source-available for transparency and security audit. All rights reserved.
No license is granted to copy, modify, redistribute, or use this code to build
a competing product. You may read and audit it. If you need a commercial
license, contact contact@stealthledger.io.
