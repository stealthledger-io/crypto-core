import Foundation

/// Platform-agnostic primitives the vault needs:
/// - PBKDF2-HMAC-SHA256 (the first and last scrypt steps)
/// - AES-256-GCM decrypt, WebCrypto `ct = ciphertext || 16-byte tag`, 12-byte IV, AAD
///
/// On Apple platforms this is backed by CryptoKit (AES.GCM + HMAC<SHA256>).
/// On Linux it is backed by OpenSSL EVP through the VAesGcm C bridge.
/// The pure-Swift scrypt (Salsa20/8, scryptBlockMix, scryptROMix) is unchanged on both.
public protocol VaultCrypto {
    func pbkdf2HmacSha256(password: [UInt8], salt: [UInt8], iterations: UInt32, dkLen: Int) -> [UInt8]?
    func aesGcmOpen(key: [UInt8], iv: [UInt8], ctWithTag: [UInt8], aad: [UInt8]) -> [UInt8]?
}

// MARK: - Apple (macOS / iOS): CryptoKit

#if os(macOS) || os(iOS)
import CryptoKit

public struct AppleCrypto: VaultCrypto {
    public init() {}

    public func pbkdf2HmacSha256(password: [UInt8], salt: [UInt8], iterations: UInt32, dkLen: Int) -> [UInt8]? {
        guard iterations > 0, dkLen > 0 else { return nil }
        let hLen = 32 // SHA-256 output length
        let blockCount = (dkLen + hLen - 1) / hLen
        let key = SymmetricKey(data: Data(password))
        var derived = [UInt8]()
        for i in 1...blockCount {
            var block = salt
            block.append(UInt8((i >> 24) & 0xFF))
            block.append(UInt8((i >> 16) & 0xFF))
            block.append(UInt8((i >> 8) & 0xFF))
            block.append(UInt8(i & 0xFF))
            var u = Array(HMAC<SHA256>.authenticationCode(for: Data(block), using: key))
            var t = u
            for _ in 1..<Int(iterations) {
                u = Array(HMAC<SHA256>.authenticationCode(for: Data(u), using: key))
                for k in 0..<t.count { t[k] ^= u[k] }
            }
            derived.append(contentsOf: t)
        }
        return Array(derived.prefix(dkLen))
    }

    public func aesGcmOpen(key: [UInt8], iv: [UInt8], ctWithTag: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard ctWithTag.count >= 16, key.count == 32, iv.count == 12 else { return nil }
        let tag = Data(ctWithTag.suffix(16))
        let ciphertext = Data(ctWithTag.prefix(ctWithTag.count - 16))
        do {
            let nonce = try AES.GCM.Nonce(data: Data(iv))
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let plain = try AES.GCM.open(box, using: SymmetricKey(data: Data(key)),
                                        authenticating: Data(aad))
            return Array(plain)
        } catch {
            return nil // auth failure / wrong key
        }
    }
}

public let crypto: VaultCrypto = AppleCrypto()

// MARK: - Linux: OpenSSL EVP via the C bridge

#else
import VAesGcm

public struct LinuxCrypto: VaultCrypto {
    public init() {}

    public func pbkdf2HmacSha256(password: [UInt8], salt: [UInt8], iterations: UInt32, dkLen: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: dkLen)
        let rc = password.withUnsafeBufferPointer { p in
            salt.withUnsafeBufferPointer { s in
                out.withUnsafeMutableBufferPointer { o in
                    pbkdf2_hmac_sha256(p.baseAddress, p.count, s.baseAddress, s.count,
                                       iterations, o.baseAddress, o.count)
                }
            }
        }
        return rc == 0 ? out : nil
    }

    public func aesGcmOpen(key: [UInt8], iv: [UInt8], ctWithTag: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard ctWithTag.count >= 16 else { return nil }
        var out = [UInt8](repeating: 0, count: ctWithTag.count - 16)
        var outLen: Int = 0
        let rc = key.withUnsafeBufferPointer { kp in
            iv.withUnsafeBufferPointer { ip in
                ctWithTag.withUnsafeBufferPointer { cp in
                    aad.withUnsafeBufferPointer { ap in
                        out.withUnsafeMutableBufferPointer { op in
                            aes256gcm_decrypt(kp.baseAddress, kp.count, ip.baseAddress, ip.count,
                                              cp.baseAddress, cp.count, ap.baseAddress, ap.count,
                                              op.baseAddress, &outLen)
                        }
                    }
                }
            }
        }
        return rc == 0 ? Array(out.prefix(outLen)) : nil
    }
}

public let crypto: VaultCrypto = LinuxCrypto()

#endif
