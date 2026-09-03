// Pure-Swift scrypt (RFC 7914). The Salsa20/8 core, scryptBlockMix and
// scryptROMix are all implemented in Swift and are identical on every platform.
// Only the PBKDF2-HMAC-SHA256 primitive is delegated to `crypto` (OpenSSL on
// Linux, CryptoKit on Apple) — the scrypt algorithm itself is platform-free.

import Foundation

@inline(__always)
private func rotl(_ x: UInt32, _ b: UInt32) -> UInt32 {
    (x &<< b) | (x &>> (32 &- b))
}

/// Salsa20/8 core: 64 bytes in -> 64 bytes out, little-endian, 8 rounds (4 double-rounds).
public func salsa20_8(_ inPtr: UnsafePointer<UInt8>, _ outPtr: UnsafeMutablePointer<UInt8>,
               _ w: UnsafeMutablePointer<UInt32>, _ wc: UnsafeMutablePointer<UInt32>) {
    var i = 0
    while i < 16 {
        let v = UInt32(inPtr[4*i]) | (UInt32(inPtr[4*i+1]) &<< 8) | (UInt32(inPtr[4*i+2]) &<< 16) | (UInt32(inPtr[4*i+3]) &<< 24)
        w[i] = v
        wc[i] = v
        i += 1
    }
    for _ in 0..<4 {
        w[4] ^= rotl(w[0] &+ w[12], 7)
        w[8] ^= rotl(w[4] &+ w[0], 9)
        w[12] ^= rotl(w[8] &+ w[4], 13)
        w[0] ^= rotl(w[12] &+ w[8], 18)
        w[9] ^= rotl(w[5] &+ w[1], 7)
        w[13] ^= rotl(w[9] &+ w[5], 9)
        w[1] ^= rotl(w[13] &+ w[9], 13)
        w[5] ^= rotl(w[1] &+ w[13], 18)
        w[14] ^= rotl(w[10] &+ w[6], 7)
        w[2] ^= rotl(w[14] &+ w[10], 9)
        w[6] ^= rotl(w[2] &+ w[14], 13)
        w[10] ^= rotl(w[6] &+ w[2], 18)
        w[3] ^= rotl(w[15] &+ w[11], 7)
        w[7] ^= rotl(w[3] &+ w[15], 9)
        w[11] ^= rotl(w[7] &+ w[3], 13)
        w[15] ^= rotl(w[11] &+ w[7], 18)
        w[1] ^= rotl(w[0] &+ w[3], 7)
        w[2] ^= rotl(w[1] &+ w[0], 9)
        w[3] ^= rotl(w[2] &+ w[1], 13)
        w[0] ^= rotl(w[3] &+ w[2], 18)
        w[6] ^= rotl(w[5] &+ w[4], 7)
        w[7] ^= rotl(w[6] &+ w[5], 9)
        w[4] ^= rotl(w[7] &+ w[6], 13)
        w[5] ^= rotl(w[4] &+ w[7], 18)
        w[11] ^= rotl(w[10] &+ w[9], 7)
        w[8] ^= rotl(w[11] &+ w[10], 9)
        w[9] ^= rotl(w[8] &+ w[11], 13)
        w[10] ^= rotl(w[9] &+ w[8], 18)
        w[12] ^= rotl(w[15] &+ w[14], 7)
        w[13] ^= rotl(w[12] &+ w[15], 9)
        w[14] ^= rotl(w[13] &+ w[12], 13)
        w[15] ^= rotl(w[14] &+ w[13], 18)
    }
    i = 0
    while i < 16 {
        let v = w[i] &+ wc[i]
        outPtr[4*i] = UInt8(truncatingIfNeeded: v)
        outPtr[4*i+1] = UInt8(truncatingIfNeeded: v &>> 8)
        outPtr[4*i+2] = UInt8(truncatingIfNeeded: v &>> 16)
        outPtr[4*i+3] = UInt8(truncatingIfNeeded: v &>> 24)
        i += 1
    }
}

/// scryptBlockMix on a 128r-byte buffer (in -> out), 2r blocks of 64 bytes.
func blockMix(inPtr: UnsafePointer<UInt8>, outPtr: UnsafeMutablePointer<UInt8>, r: Int,
              _ X: UnsafeMutablePointer<UInt8>,
              _ w: UnsafeMutablePointer<UInt32>, _ wc: UnsafeMutablePointer<UInt32>) {
    let blocks = 2 * r
    // X = last block of input
    memcpy(X, inPtr + (blocks - 1) * 64, 64)
    for i in 0..<blocks {
        for k in 0..<64 { X[k] ^= inPtr[i*64 + k] }
        salsa20_8(X, X, w, wc)
        // output ordering: even blocks first, then odd blocks
        let outIndex = (i % 2 == 0) ? (i / 2) : (r + i / 2)
        memcpy(outPtr + outIndex*64, X, 64)
    }
}

func integerify(xPtr: UnsafePointer<UInt8>, r: Int) -> UInt64 {
    let base = (2 * r - 1) * 64
    var v: UInt64 = 0
    for k in 0..<8 {
        v |= UInt64(xPtr[base + k]) &<< (8 * k)
    }
    return v
}

func romix(_ input: UnsafePointer<UInt8>, _ output: UnsafeMutablePointer<UInt8>, N: Int, r: Int) {
    let chunk = 128 * r
    var V = [UInt8](repeating: 0, count: N * chunk)
    var next = [UInt8](repeating: 0, count: chunk)
    var X = Array(UnsafeBufferPointer(start: input, count: chunk))

    let Xscratch = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
    let w = UnsafeMutablePointer<UInt32>.allocate(capacity: 16)
    let wc = UnsafeMutablePointer<UInt32>.allocate(capacity: 16)
    defer {
        Xscratch.deallocate()
        w.deallocate()
        wc.deallocate()
    }

    // First loop: fill V, walk X forward.
    for i in 0..<N {
        X.withUnsafeBufferPointer { xb in
            V.withUnsafeMutableBufferPointer { vb in
                _ = memcpy(vb.baseAddress! + i*chunk, xb.baseAddress!, chunk)
            }
        }
        next.withUnsafeMutableBufferPointer { np in
            X.withUnsafeBufferPointer { xb in
                blockMix(inPtr: xb.baseAddress!, outPtr: np.baseAddress!, r: r, Xscratch, w, wc)
            }
        }
        swap(&X, &next)
    }
    // Second loop: pseudo-random lookups into V.
    for _ in 0..<N {
        let j = Int(integerify(xPtr: X, r: r) % UInt64(N))
        for k in 0..<chunk { X[k] ^= V[j*chunk + k] }
        next.withUnsafeMutableBufferPointer { np in
            X.withUnsafeBufferPointer { xb in
                blockMix(inPtr: xb.baseAddress!, outPtr: np.baseAddress!, r: r, Xscratch, w, wc)
            }
        }
        swap(&X, &next)
    }
    output.update(from: X, count: chunk)
}

/// scrypt(P, S, N, r, p, dkLen) -> derived key.
public func scrypt(password: [UInt8], salt: [UInt8], N: Int, r: Int, p: Int, dkLen: Int) -> [UInt8]? {
    let chunk = 128 * r
    guard let B0 = crypto.pbkdf2HmacSha256(password: password, salt: salt, iterations: 1, dkLen: p * chunk) else {
        return nil
    }
    var B = B0

    for i in 0..<p {
        let lo = i * chunk
        let mixed: [UInt8] = B[lo..<(lo+chunk)].withUnsafeBufferPointer { ptr -> [UInt8] in
            var out = [UInt8](repeating: 0, count: chunk)
            out.withUnsafeMutableBufferPointer { op in
                romix(ptr.baseAddress!, op.baseAddress!, N: N, r: r)
            }
            return out
        }
        for k in 0..<chunk { B[lo + k] = mixed[k] }
    }

    return crypto.pbkdf2HmacSha256(password: password, salt: B, iterations: 1, dkLen: dkLen)
}
