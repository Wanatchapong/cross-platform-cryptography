const crypto = require('crypto')

function aes256CbcEncrypt(text, password) {
    const saltBuffer = crypto.randomBytes(16) // 16 bytes
    const ivBuffer = crypto.randomBytes(16) // 16 bytes

    const iterationCount = 10000
    const keyLen = 32 // 256 bits
    const key = crypto.pbkdf2Sync(password, saltBuffer, iterationCount, keyLen, 'sha256')
  
    const cipher = crypto.createCipheriv('aes-256-cbc', key, ivBuffer)
    cipher.write(text)
    cipher.end()
    const encryptedBuffer = cipher.read()
  
    return Buffer.concat([saltBuffer, ivBuffer, encryptedBuffer]).toString('base64')
}

function aes256CbcDecrypt(encrypted, password) {  
    const concatenatedBuffer = Buffer.from(encrypted, 'base64')

    const saltBuffer = concatenatedBuffer.subarray(0, 16)
    const ivBuffer = concatenatedBuffer.subarray(16, 32)
    const encryptedBuffer = concatenatedBuffer.subarray(32)
  
    const iterationCount = 10000
    const keyLen = 32
    const key = crypto.pbkdf2Sync(password, saltBuffer, iterationCount, keyLen, 'sha256')
  
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer)
    decipher.write(encryptedBuffer)
    decipher.end()
    const decrypted = decipher.read()
    return decrypted.toString()
}

module.exports = {
    aes256CbcEncrypt,
    aes256CbcDecrypt
}