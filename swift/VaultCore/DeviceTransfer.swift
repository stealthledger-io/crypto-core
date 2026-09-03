import Foundation
#if os(macOS) || os(iOS)
import CryptoKit
#endif

// Device vault-key transfer ("zero typing" pairing) — the iOS mirror of the
// website's sealContentKeyForTransfer / openContentKeyFromTransfer.
//
// The phone generates an ephemeral P-256 keypair, posts only the public key
// (SPKI DER, base64) to the relay, and polls for a ciphertext the website
// sealed to that key. It then derives the same ECDH shared secret + HKDF key
// and decrypts the contentKey locally. The private key never leaves the
// device and is wiped after use; the contentKey goes into the Keychain.

/// The grant record the phone receives after the website seals the contentKey.
/// Mirrors the JSON returned by GET /api/auth/device-cipher.
public struct TransferredGrant: Decodable {
    public let status: String
    public let transferId: String
    public let userId: String
    public let senderPubKey: String   // SPKI DER, base64
    public let salt: String           // HKDF salt, base64
    public let nonce: String          // AES-GCM 12-byte IV, base64
    public let ct: String              // ciphertext || 16-byte tag, base64
    public let alg: String            // "AES-256-GCM"
    public let fingerprint: String    // SHA-256 hex of the phone pubkey

    public init(status: String, transferId: String, userId: String, senderPubKey: String,
                salt: String, nonce: String, ct: String, alg: String, fingerprint: String) {
        self.status = status; self.transferId = transferId; self.userId = userId
        self.senderPubKey = senderPubKey; self.salt = salt; self.nonce = nonce
        self.ct = ct; self.alg = alg; self.fingerprint = fingerprint
    }
}

/// The plaintext payload inside the sealed grant. The contentKey is the vault
/// DEK (32 bytes, base64). transferId + alg are echoed so the phone can reject
/// a grant grafted onto the wrong transfer.
public struct TransferredContentKey: Decodable {
    public let contentKey: String
    public let transferId: String
    public let createdAt: String
    public let alg: String
}

#if os(macOS) || os(iOS)

/// Domain-separated HKDF label. Must match the website's TRANSFER_INFO.
private let TRANSFER_INFO = "StealthLedger vault key transfer v1"

/// Build the AAD string. Must match the website's transferAad exactly:
///   SL1|transferId|userId|fingerprint|alg
private func transferAad(transferId: String, userId: String, fingerprint: String, alg: String) -> String {
    "SL1|\(transferId)|\(userId)|\(fingerprint)|\(alg)"
}

/// Decrypt a transferred contentKey grant with the phone's ephemeral P-256
/// private key. Returns the raw 32-byte contentKey, or nil on any failure
/// (wrong key, tampered ciphertext, mismatched transferId/alg). Mirrors the
/// website's openContentKeyFromTransfer.
public func openTransferredContentKey(grant: TransferredGrant,
                                      phonePrivateKey: P256.KeyAgreement.PrivateKey) -> [UInt8]? {
    do {
        guard grant.status == "granted",
              let senderPubData = Data(base64Encoded: grant.senderPubKey),
              let salt = Data(base64Encoded: grant.salt),
              let nonceData = Data(base64Encoded: grant.nonce),
              let ctWithTag = Data(base64Encoded: grant.ct) else { return nil }
        let ctLen = ctWithTag.count - 16
        guard ctLen > 0 else { return nil }

        // ECDH: phone private key x website ephemeral public key.
        let senderPub = try P256.KeyAgreement.PublicKey(derRepresentation: senderPubData)
        let shared = try phonePrivateKey.sharedSecretFromKeyAgreement(with: senderPub)

        // HKDF-SHA256 -> transfer key (SymmetricKey; raw bytes never extracted).
        let transferKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(TRANSFER_INFO.utf8), outputByteCount: 32)

        // AES-256-GCM open. WebCrypto ct layout is ciphertext || 16-byte tag.
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce,
                                        ciphertext: Data(ctWithTag.prefix(ctLen)),
                                        tag: Data(ctWithTag.suffix(16)))
        let aad = transferAad(transferId: grant.transferId, userId: grant.userId,
                              fingerprint: grant.fingerprint, alg: grant.alg)
        let plaintext = try AES.GCM.open(box, using: transferKey,
                                        authenticating: Data(aad.utf8))

        let payload = try JSONDecoder().decode(TransferredContentKey.self, from: plaintext)
        guard payload.transferId == grant.transferId, payload.alg == grant.alg else { return nil }
        let contentKey = b64decode(payload.contentKey)
        guard contentKey.count == 32 else { return nil }
        return contentKey
    } catch {
        return nil
    }
}

/// Generate a fresh ephemeral P-256 keypair for a single transfer. The private
/// key is held in memory only for the duration of the transfer and wiped after.
public func newDeviceTransferKeyPair() -> P256.KeyAgreement.PrivateKey {
    return P256.KeyAgreement.PrivateKey()
}

/// Export the phone's ephemeral public key as SPKI DER, base64 — the wire form
/// the server stores and the website imports for ECDH.
public func deviceTransferPublicKeyB64(_ privateKey: P256.KeyAgreement.PrivateKey) -> String {
    return privateKey.publicKey.derRepresentation.base64EncodedString()
}

/// SHA-256 of the UTF-8 bytes of a public-key string, as lowercase hex. This is
/// the fingerprint the phone computes locally from its own pubkey and displays
/// for TOFU — it must NOT trust the relay's reported fingerprint, since a
/// malicious relay could show the same fake value on both screens.
public func deviceTransferFingerprint(_ pubKeyB64: String) -> String {
    let digest = SHA256.hash(data: Data(pubKeyB64.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}

#endif
