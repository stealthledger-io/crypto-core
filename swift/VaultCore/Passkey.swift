import Foundation
#if os(macOS) || os(iOS)
import CryptoKit
#endif

// Passkey (WebAuthn PRF) vault unlocker.
//
// This mirrors the website's passkey.js + vault-core.js PRF path. The passkey
// is used as a hardware key-derivation oracle, NOT for server authentication:
// the challenge is client-generated and the assertion signature is never
// verified. Security comes from the Secure Enclave refusing to run the PRF
// without a live biometric, and a wrong PRF output produces a KEK that fails
// AES-GCM authentication on the wrapped content key.
//
// Flow:
//   1. prfSalt = SHA256("portcalc:prf:v2:" + vaultId)
//   2. prfOutput = authenticator.PRF(credential, prfSalt)   [32 bytes, biometric-gated]
//   3. kek = HKDF-SHA256(ikm=prfOutput, salt=hkdfSalt, info="portcalc:passkey-kek:v2", len=32)
//   4. contentKey = AES-256-GCM-Open(kek, slot.wrap, aad=wrapAad)

/// PRF salt derivation info. Must match the website's PRF_SALT_INFO.
public let PRF_SALT_INFO = "portcalc:prf:v2"

/// HKDF info for the passkey KEK. Must match the website's PASSKEY_HKDF_INFO.
public let PASSKEY_HKDF_INFO = "portcalc:passkey-kek:v2"

/// Content key length in bytes (256-bit).
public let PASSKEY_KEY_LEN = 32

/// The PRF salt fed to the authenticator. Derived from vaultId so it is stable
/// across devices and domain-separated. Mirrors vault-core.js prfSaltFor.
public func prfSaltFor(vaultId: String) -> [UInt8] {
    let input = "\(PRF_SALT_INFO):\(vaultId)"
    #if os(macOS) || os(iOS)
    return Array(SHA256.hash(data: Data(input.utf8)))
    #else
    return Array(crypto.sha256(Array(input.utf8)))
    #endif
}

#if os(macOS) || os(iOS)

private func randomBytes(_ count: Int) -> [UInt8] {
    let key = SymmetricKey(size: SymmetricKeySize(bitCount: max(8, count * 8)))
    return key.withUnsafeBytes { Array($0) }
}

private func iso8601Now() -> String {
    ISO8601DateFormatter().string(from: Date())
}

/// HKDF-SHA256 over raw input key material. Mirrors WebCrypto
/// subtle.deriveBits({name:"HKDF", hash:"SHA-256", salt, info}, ikm, len*8).
public func hkdfSha256(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8]? {
    guard ikm.count > 0, length > 0 else { return nil }
    let derived = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: Data(ikm)),
        salt: Data(salt),
        info: Data(info),
        outputByteCount: length)
    return derived.withUnsafeBytes { Array($0) }
}

/// Create a passkey unlocker slot wrapping the content key under a PRF-derived
/// KEK. Mirrors vault-core.js addPasskeyUnlocker. The caller supplies the raw
/// PRF output harvested from the ASAuthorization assertion; this function never
/// touches the authenticator itself, so it stays testable without a device.
///
/// - Returns: a new Envelope with the passkey slot appended, or nil on failure.
public func addPasskeyUnlocker(envelope: Envelope,
                               contentKey: [UInt8],
                               credentialId: String,
                               prfOutput: [UInt8],
                               label: String = "Face ID",
                               transports: [String] = []) -> Envelope? {
    guard contentKey.count == PASSKEY_KEY_LEN else { return nil }
    guard prfOutput.count >= PASSKEY_KEY_LEN else { return nil }

    let slotId = hex(randomBytes(8))
    let now = iso8601Now()
    // Per-slot HKDF salt so the KEK is unique to this vault even if the same
    // credential and PRF salt were ever reused elsewhere.
    let hkdfSalt = randomBytes(32)
    let stub = Unlocker(id: slotId, type: "passkey", label: label, kdf: nil,
                        wrap: nil, createdAt: now, lastUsedAt: nil,
                        credentialId: credentialId, transports: transports,
                        hkdfSalt: b64encode(hkdfSalt))

    guard let kek = hkdfSha256(ikm: prfOutput, salt: hkdfSalt,
                               info: Array(PASSKEY_HKDF_INFO.utf8),
                               length: PASSKEY_KEY_LEN) else { return nil }
    guard let wrapSealed = aesGcmSeal(key: kek, plaintext: contentKey,
                                      aad: wrapAad(vaultId: envelope.vaultId, slot: stub)) else {
        return nil
    }
    let slot = Unlocker(id: slotId, type: "passkey", label: label, kdf: nil,
                        wrap: SealedBlob(alg: "AES-256-GCM",
                                         iv: b64encode(wrapSealed.iv),
                                         ct: b64encode(wrapSealed.ctWithTag)),
                        createdAt: now, lastUsedAt: nil,
                        credentialId: credentialId, transports: transports,
                        hkdfSalt: b64encode(hkdfSalt))
    return Envelope(v: envelope.v, kind: envelope.kind, vaultId: envelope.vaultId,
                    seq: envelope.seq, content: envelope.content,
                    unlockers: envelope.unlockers + [slot], updatedAt: now)
}

/// Unwrap the content key using a passkey's PRF output. Mirrors vault-core.js
/// unlockWithPasskeyPrf. Returns the raw 32-byte content key plus the slot that
/// matched, so the caller can later re-seal edits under the same key.
public func unlockWithPasskeyPrf(envelope: Envelope,
                                 credentialId: String,
                                 prfOutput: [UInt8]) -> (contentKey: [UInt8], slot: Unlocker)? {
    let slot = envelope.unlockers.first { $0.type == "passkey" && $0.credentialId == credentialId }
    guard let slot = slot, slot.wrap != nil, let saltB64 = slot.hkdfSalt else { return nil }
    let salt = b64decode(saltB64)
    guard salt.count == PASSKEY_KEY_LEN else { return nil }
    guard let kek = hkdfSha256(ikm: prfOutput, salt: salt,
                               info: Array(PASSKEY_HKDF_INFO.utf8),
                               length: PASSKEY_KEY_LEN) else { return nil }
    guard let contentKey = aesGcmOpen(key: kek, sealed: slot.wrap!,
                                     aad: wrapAad(vaultId: envelope.vaultId, slot: slot)) else {
        return nil
    }
    return (contentKey, slot)
}

#endif
