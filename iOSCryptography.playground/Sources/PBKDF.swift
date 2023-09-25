import Foundation
import CommonCrypto

public final class PBKDF {
    func pbkdf2SHA1(password: String, salt: Data, iterationRounds: Int, keyByteCount: Int) -> Data? {
        return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, iterationRounds: iterationRounds, keyByteCount: keyByteCount)
    }

    func pbkdf2SHA256(password: String, salt: Data, iterationRounds: Int, keyByteCount: Int) -> Data? {
        return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, iterationRounds: iterationRounds, keyByteCount: keyByteCount)
    }

    func pbkdf2SHA512(password: String, salt: Data, iterationRounds: Int, keyByteCount: Int) -> Data? {
        return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, iterationRounds: iterationRounds, keyByteCount: keyByteCount)
    }

    func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, iterationRounds: Int, keyByteCount: Int) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }

        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let derivedKeyCount = derivedKeyData.count

        let status = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
              CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    passwordData.count,
                    saltBytes.baseAddress,
                    salt.count,
                    hash,
                    UInt32(iterationRounds),
                    derivedKeyBytes.baseAddress,
                    derivedKeyCount)
            }
        }

        guard status == kCCSuccess else {
            return nil
        }

        return derivedKeyData
    }

    func testKeyDerivation() {
        let password = "password"
        let salt = Data([0x73, 0x61, 0x6C, 0x74, 0x44, 0x61, 0x74, 0x61])
        let keyByteCount = 32
        let iterationRounds = 10_000

        _ = pbkdf2SHA1(password: password, salt: salt, iterationRounds: iterationRounds, keyByteCount: keyByteCount)
    }
}
