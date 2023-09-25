import Foundation
import CommonCrypto

public class Cryptography {

    public enum Error: Swift.Error {
        case invalidKey
        case invalidInitializationVector
        case encryptionError
        case decryptionError
    }

    public static func aes256CbcEncrypt(text: String, password: String) throws -> String {
        let textData = text.data(using: .utf8)!

        let saltCount = kCCBlockSizeAES128 // 16 bytes
        let ivCount = kCCBlockSizeAES128 // 16 bytes

        let saltData = randomData(count: saltCount)
        let ivData = randomData(count: ivCount)

        let iterationRounds = 10_000
        let keyByteCount = kCCKeySizeAES256 // 32 bytes
        let keyData = PBKDF().pbkdf2SHA256(password: password, salt: saltData, iterationRounds: iterationRounds, keyByteCount: keyByteCount)

        // Output buffer (with padding)
        let outputCount = textData.count + kCCBlockSizeAES128
        var outputBuffer = Array<UInt8>(repeating: 0, count: outputCount)
        var numBytesEncrypted = 0

        let status = keyData?.withUnsafeBytes { keyBytes in
            ivData.withUnsafeBytes { ivBytes in
                textData.withUnsafeBytes { textBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress,
                        keyData!.count,
                        ivBytes.baseAddress,
                        textBytes.baseAddress,
                        textData.count,
                        &outputBuffer,
                        outputCount,
                        &numBytesEncrypted
                    )
                }
            }
        }

        guard status == CCCryptorStatus(kCCSuccess) else {
            throw Error.encryptionError
        }

        let encryptedData = Data(outputBuffer.prefix(numBytesEncrypted))
        let concatenatedData = saltData + ivData + encryptedData
        return concatenatedData.base64EncodedString()
    }
    
    public static func aes256CbcDecrypt(encryptedBase64: String, password: String) throws -> String {
        guard let concatenatedData: Data = Data(base64Encoded: encryptedBase64) else {
            throw Error.decryptionError
        }
        
        let saltCount = kCCBlockSizeAES128
        let ivCount = saltCount + kCCBlockSizeAES128

        let saltData = concatenatedData.prefix(saltCount)
        let ivData = concatenatedData.subdata(in: saltCount..<ivCount)
        let encryptedData = concatenatedData.subdata(in: ivCount..<concatenatedData.count)
        
        let iterationRounds = 10_000
        let keyByteCount = kCCKeySizeAES256
        let keyData = PBKDF().pbkdf2SHA256(password: password, salt: saltData, iterationRounds: iterationRounds, keyByteCount: keyByteCount)
        
        let outputCount = encryptedData.count + kCCBlockSizeAES128
        var outputBuffer = Array<UInt8>(repeating: 0, count: outputCount)
        var numBytesDecrypted = 0

        let status = keyData?.withUnsafeBytes { keyBytes in
            ivData.withUnsafeBytes { ivBytes in
                encryptedData.withUnsafeBytes { encryptedBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress,
                        keyData!.count,
                        ivBytes.baseAddress,
                        encryptedBytes.baseAddress,
                        encryptedData.count,
                        &outputBuffer,
                        outputCount,
                        &numBytesDecrypted
                    )
                }
            }
        }

        guard status == CCCryptorStatus(kCCSuccess) else {
            throw Error.decryptionError
        }
        
        let decryptedData = Data(outputBuffer.prefix(numBytesDecrypted))

        guard let decryptedText = String(data: decryptedData, encoding: .utf8) else {
            throw Error.decryptionError
        }

        return decryptedText
    }

    public static func randomData(count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { mutableBytes in
          SecRandomCopyBytes(kSecRandomDefault, count, mutableBytes.baseAddress!)
        }
        return data
    }
}
