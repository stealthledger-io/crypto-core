import Foundation

/// StealthLedger login proof derivation.
///
/// Mirrors `scryptProof(password, saltBytes)` in the web auth module:
/// the typed passphrase is encoded as raw UTF-8 bytes (NO NFKC normalization —
/// that is applied only to the vault DEK passphrase, not the login proof) and
/// stretched with scrypt using the login salt returned by /api/auth/salt.
///
///   proof = scrypt(utf8(loginPass), loginSalt, N=65536, r=8, p=1, dkLen=32)
///
/// The returned 32 bytes are base64-encoded by the caller and posted as
/// `{ username, proof }` to /api/auth/login.
public enum LoginScrypt {
    public static let N = 65536
    public static let r = 8
    public static let p = 1
    public static let dkLen = 32

    /// Derive the login proof bytes from a passphrase and a base64-decoded salt.
    public static func proof(passphrase: String, salt: [UInt8]) -> [UInt8]? {
        // Intentionally raw UTF-8, NOT NFKC — matches the web login path.
        let passBytes = Array(passphrase.utf8)
        return scrypt(password: passBytes, salt: salt, N: N, r: r, p: p, dkLen: dkLen)
    }
}
