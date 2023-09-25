package me.cryptography

import org.junit.jupiter.api.Test

class CryptographyTest {
    private val cryptography: Cryptography = Cryptography()

    @Test
    fun testAES256CBCEncryptDecrypt() {
        val text = "Abc1234"
        val password = "MyPassword"

        val encrypted = cryptography.aes256CbcEncrypt(text, password)
        val decrypted = cryptography.aes256CbcDecrypt(encrypted, password)

        println("Encrypted: $encrypted\nDecrypted: $decrypted")
    }
}