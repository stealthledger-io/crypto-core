import Foundation
#if os(macOS) || os(iOS)
import CryptoKit
#endif

public struct SealedBlob: Codable {
    public let alg: String?
    public let iv: String
    public let ct: String
    public init(alg: String?, iv: String, ct: String) {
        self.alg = alg; self.iv = iv; self.ct = ct
    }
}

public struct KdfParams: Codable {
    public let name: String?
    public let N: Int
    public let r: Int
    public let p: Int
    public let salt: String
    public init(name: String?, N: Int, r: Int, p: Int, salt: String) {
        self.name = name; self.N = N; self.r = r; self.p = p; self.salt = salt
    }
}

public struct Unlocker: Codable {
    public let id: String
    public let type: String
    public let label: String?
    public let kdf: KdfParams?
    public let wrap: SealedBlob?
    public let credentialId: String?
    public let transports: [String]?
    public let hkdfSalt: String?
    public let createdAt: String?
    public let lastUsedAt: String?
    public init(id: String, type: String, label: String?, kdf: KdfParams?,
                wrap: SealedBlob?, createdAt: String? = nil, lastUsedAt: String? = nil,
                credentialId: String? = nil, transports: [String]? = nil,
                hkdfSalt: String? = nil) {
        self.id = id; self.type = type; self.label = label; self.kdf = kdf; self.wrap = wrap
        self.createdAt = createdAt; self.lastUsedAt = lastUsedAt
        self.credentialId = credentialId; self.transports = transports; self.hkdfSalt = hkdfSalt
    }
}

public struct Envelope: Codable {
    public let v: Int
    public let kind: String
    public let vaultId: String
    public let seq: Int?
    public let updatedAt: String?
    public let content: SealedBlob
    public let unlockers: [Unlocker]
    public init(v: Int, kind: String, vaultId: String, seq: Int?,
                content: SealedBlob, unlockers: [Unlocker], updatedAt: String? = nil) {
        self.v = v; self.kind = kind; self.vaultId = vaultId; self.seq = seq
        self.content = content; self.unlockers = unlockers; self.updatedAt = updatedAt
    }
}

public func wrapAad(vaultId: String, slot: Unlocker) -> String {
    "portcalc-vault:v2:\(vaultId):unlocker:\(slot.id):\(slot.type)"
}

public func contentAad(vaultId: String) -> String {
    "portcalc-vault:v2:\(vaultId):content"
}

/// AES-256-GCM open over a WebCrypto `ct || 16-byte tag` sealed blob.
public func aesGcmOpen(key: [UInt8], sealed: SealedBlob, aad: String) -> [UInt8]? {
    let iv = b64decode(sealed.iv)
    let ct = b64decode(sealed.ct)
    let aadBytes = Array(aad.utf8)
    return crypto.aesGcmOpen(key: key, iv: iv, ctWithTag: ct, aad: aadBytes)
}

/// Derive the KEK from a passphrase slot exactly as the web vault does.
public func deriveKek(passphrase: String, slot: Unlocker) -> [UInt8]? {
    guard slot.type == "passphrase" || slot.type == "recovery",
          let kdf = slot.kdf else { return nil }
    // Strict allowlist: only the v2 scrypt contract is accepted. A malicious
    // server could otherwise hand back DoS-grade params (huge N/r/p) that hang
    // or crash the app. If the contract changes, make this a versioned list.
    guard (kdf.name == nil || kdf.name == "scrypt"),
          kdf.N == 65536, kdf.r == 8, kdf.p == 1 else { return nil }
    let secret = (slot.type == "recovery")
        ? passphrase.uppercased().filter { $0.isLetter || $0.isNumber }
        : passphrase
    // NFKC, matching the web implementation's secret.normalize('NFKC').
    let normalized = secret.precomposedStringWithCompatibilityMapping
    let pw = Array(normalized.utf8)
    let salt = b64decode(kdf.salt)
    return scrypt(password: pw, salt: salt, N: kdf.N, r: kdf.r, p: kdf.p, dkLen: 32)
}

/// Open a passphrase-protected vault, returning the decrypted payload bytes.
/// Tries EVERY passphrase-type unlocker slot and returns the first that
/// unwraps. A vault can have several passphrase slots (e.g. an older
/// recovery phrase from signup plus a newly generated one); trying only the
/// first would fail to open with the newer phrase even though it is valid.
public func openVault(envelope: Envelope, passphrase: String) -> [UInt8]? {
    for slot in envelope.unlockers where slot.type == "passphrase" {
        guard slot.wrap != nil else { continue }
        guard let kek = deriveKek(passphrase: passphrase, slot: slot) else { continue }
        guard let contentKey = aesGcmOpen(key: kek, sealed: slot.wrap!, aad: wrapAad(vaultId: envelope.vaultId, slot: slot)) else {
            continue
        }
        guard let payload = aesGcmOpen(key: contentKey, sealed: envelope.content, aad: contentAad(vaultId: envelope.vaultId)) else {
            continue
        }
        return payload
    }
    return nil
}

/// Convenience: decode an envelope from JSON and open it with a passphrase.
public func unlockVault(jsonData: Data, passphrase: String) -> [UInt8]? {
    guard let envelope = try? JSONDecoder().decode(Envelope.self, from: jsonData) else { return nil }
    return openVault(envelope: envelope, passphrase: passphrase)
}

/// Open a vault with its 25-character recovery code (a recovery-type unlocker
/// slot). Mirrors openVault but resolves the recovery slot instead of the
/// passphrase slot. The recovery code is uppercased and stripped to
/// alphanumeric by deriveKek, matching the website. Returns nil if there is
/// no recovery slot or the code is wrong.
public func openVaultWithRecovery(envelope: Envelope, recoveryCode: String) -> [UInt8]? {
    guard let slot = envelope.unlockers.first(where: { $0.type == "recovery" }),
          slot.wrap != nil else { return nil }
    guard let kek = deriveKek(passphrase: recoveryCode, slot: slot) else { return nil }
    guard let contentKey = aesGcmOpen(key: kek, sealed: slot.wrap!, aad: wrapAad(vaultId: envelope.vaultId, slot: slot)) else {
        return nil
    }
    guard let payload = aesGcmOpen(key: contentKey, sealed: envelope.content, aad: contentAad(vaultId: envelope.vaultId)) else {
        return nil
    }
    return payload
}

/// Try the passphrase slot, then fall back to the recovery-code slot,
/// returning the first payload that decrypts. Used by the iOS unlock step when
/// the login passphrase may differ from the current vault passphrase.
public func openVault(envelope: Envelope, passphrase: String, recoveryCode: String) -> [UInt8]? {
    if let payload = openVault(envelope: envelope, passphrase: passphrase) { return payload }
    guard !recoveryCode.isEmpty else { return nil }
    return openVaultWithRecovery(envelope: envelope, recoveryCode: recoveryCode)
}

/// Open a vault with a raw content key (the DEK) transferred from another
/// device, skipping the passphrase/recovery unwrap entirely. This is the
/// "zero-typing" path: the phone received the contentKey sealed to its
/// ephemeral P-256 key, decrypted it locally, and now opens the payload with
/// it. The contentKey is the same key the passphrase slot wraps, so any
/// existing unlocker still works alongside it.
public func openVaultWithContentKey(envelope: Envelope, contentKey: [UInt8]) -> [UInt8]? {
    guard contentKey.count == 32 else { return nil }
    return aesGcmOpen(key: contentKey, sealed: envelope.content,
                     aad: contentAad(vaultId: envelope.vaultId))
}

#if os(macOS) || os(iOS)

/// AES-256-GCM seal producing a WebCrypto-compatible sealed blob (12-byte IV,
/// ciphertext || 16-byte tag). Inverse of `aesGcmOpen`.
public func aesGcmSeal(key: [UInt8], plaintext: [UInt8], aad: String) -> (iv: [UInt8], ctWithTag: [UInt8])? {
    guard key.count == 32 else { return nil }
    do {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data(plaintext), using: SymmetricKey(data: Data(key)),
                                     nonce: nonce, authenticating: Data(Array(aad.utf8)))
        var ctWithTag = Array(sealed.ciphertext)
        ctWithTag.append(contentsOf: Array(sealed.tag))
        let iv = sealed.nonce.withUnsafeBytes { Array($0) }
        return (iv, ctWithTag)
    } catch {
        return nil
    }
}

/// Re-seal a vault with new plaintext, preserving vaultId / version / kind /
/// unlockers. The content key is re-derived from the passphrase slot (same
/// path as `openVault`), then the new payload is sealed under it. `nextSeq` is
/// the seq the caller expects the server to accept (expectedSeq + 1).
public func sealVault(envelope: Envelope, passphrase: String, plaintext: [UInt8],
                     nextSeq: Int) -> Envelope? {
    guard let slot = envelope.unlockers.first(where: { $0.type == "passphrase" }),
          slot.wrap != nil else { return nil }
    guard let kek = deriveKek(passphrase: passphrase, slot: slot) else { return nil }
    guard let contentKey = aesGcmOpen(key: kek, sealed: slot.wrap!,
                                     aad: wrapAad(vaultId: envelope.vaultId, slot: slot)) else { return nil }
    guard let sealed = aesGcmSeal(key: contentKey, plaintext: plaintext,
                                 aad: contentAad(vaultId: envelope.vaultId)) else { return nil }
    let blob = SealedBlob(alg: envelope.content.alg,
                         iv: b64encode(sealed.iv), ct: b64encode(sealed.ctWithTag))
    return Envelope(v: envelope.v, kind: envelope.kind, vaultId: envelope.vaultId,
                   seq: nextSeq, content: blob, unlockers: envelope.unlockers)
}

/// Re-seal a vault using a raw content key (the DEK) transferred from another
/// device, preserving vaultId / version / kind / unlockers. This is the save
/// path for the "zero-typing" mode: the phone never holds the passphrase, so it
/// re-seals edits directly under the transferred contentKey. Because the
/// contentKey is the same key the passphrase slot wraps, existing unlockers are
/// untouched and still work.
public func sealVaultWithContentKey(envelope: Envelope, contentKey: [UInt8],
                                  plaintext: [UInt8], nextSeq: Int) -> Envelope? {
    guard contentKey.count == 32 else { return nil }
    guard let sealed = aesGcmSeal(key: contentKey, plaintext: plaintext,
                                  aad: contentAad(vaultId: envelope.vaultId)) else { return nil }
    let blob = SealedBlob(alg: envelope.content.alg,
                         iv: b64encode(sealed.iv), ct: b64encode(sealed.ctWithTag))
    return Envelope(v: envelope.v, kind: envelope.kind, vaultId: envelope.vaultId,
                   seq: nextSeq, content: blob, unlockers: envelope.unlockers)
}

/// Cryptographically random bytes via CryptoKit.
private func randomBytes(_ count: Int) -> [UInt8] {
    let key = SymmetricKey(size: SymmetricKeySize(bitCount: max(8, count * 8)))
    return key.withUnsafeBytes { Array($0) }
}

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func iso8601Now() -> String {
    ISO8601DateFormatter().string(from: Date())
}

/// Create a brand-new vault envelope from scratch (the inverse of the browser's
/// `createVault` + `addPassphraseUnlocker`). Generates a fresh vaultId and
/// content key, seals the payload under the content key, then wraps the content
/// key under a passphrase-derived KEK. The passphrase never leaves the device.
public func createVault(passphrase: String, plaintext: [UInt8]) -> Envelope? {
    let vaultId = hexString(randomBytes(8)) // 16 lowercase hex chars
    let contentKey = randomBytes(32)
    let now = iso8601Now()
    let slotId = hexString(randomBytes(8))
    let kdf = KdfParams(name: "scrypt", N: 65536, r: 8, p: 1,
                        salt: b64encode(randomBytes(16)))
    let stubSlot = Unlocker(id: slotId, type: "passphrase", label: "Passphrase",
                            kdf: kdf, wrap: nil)
    guard let kek = deriveKek(passphrase: passphrase, slot: stubSlot) else { return nil }
    // Wrap the content key under the passphrase KEK.
    guard let wrapSealed = aesGcmSeal(key: kek, plaintext: contentKey,
                                     aad: wrapAad(vaultId: vaultId, slot: stubSlot)) else { return nil }
    let wrappedSlot = Unlocker(id: slotId, type: "passphrase", label: "Passphrase",
                               kdf: kdf,
                               wrap: SealedBlob(alg: "AES-256-GCM",
                                                iv: b64encode(wrapSealed.iv),
                                                ct: b64encode(wrapSealed.ctWithTag)),
                               createdAt: now, lastUsedAt: nil)
    // Seal the payload under the content key.
    guard let contentSealed = aesGcmSeal(key: contentKey, plaintext: plaintext,
                                        aad: contentAad(vaultId: vaultId)) else { return nil }
    let content = SealedBlob(alg: "AES-256-GCM",
                             iv: b64encode(contentSealed.iv),
                             ct: b64encode(contentSealed.ctWithTag))
    return Envelope(v: 2, kind: "portcalc-vault", vaultId: vaultId, seq: 1,
                   content: content, unlockers: [wrappedSlot], updatedAt: now)
}
#endif
