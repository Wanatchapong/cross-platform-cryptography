import UIKit

let text = "Abc1234"
let password = "MyPassword"

let encrypted = try Cryptography.aes256CbcEncrypt(text: text, password: password)
let decrypted = try Cryptography.aes256CbcDecrypt(encryptedBase64: encrypted, password: password)

print("Encrypted: \(encrypted)\nDecrypted: \(decrypted)")
