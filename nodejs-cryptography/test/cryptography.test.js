const { expect } = require('chai')

const cryptography = require('../src/cryptography')

describe('Cryptography', () => {

    describe('testAES256CBCEncryptDecrypt', () => {
        const text = "Abc1234"
        const password = "MyPassword"

        const encrypted = cryptography.aes256CbcEncrypt(text, password)
        const decrypted = cryptography.aes256CbcDecrypt(encrypted, password)

        console.log(`Encrypted: ${encrypted}\nDecrypted: ${decrypted}`)

        expect(decrypted).to.be.equal(text)
    })
})