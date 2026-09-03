import Foundation

/// Lowercase hex encoding of a byte buffer.
public func hex(_ b: [UInt8]) -> String {
    b.map { String(format: "%02x", $0) }.joined()
}

/// Standard base64 decode, tolerating missing padding and whitespace.
public func b64decode(_ s: String) -> [UInt8] {
    var t = s
    while t.count % 4 != 0 { t.append("=") }
    if let d = Data(base64Encoded: t, options: [.ignoreUnknownCharacters]) {
        return [UInt8](d)
    }
    return []
}

/// Standard base64 encode.
public func b64encode(_ b: [UInt8]) -> String {
    Data(b).base64EncodedString()
}
