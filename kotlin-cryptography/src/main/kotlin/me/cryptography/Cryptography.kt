package me.cryptography

import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Cryptography {

    fun aes256CbcEncrypt(text: String, password: String): String {
        val saltBytes = randomBytes(16)
        val ivBytes = randomBytes(16)

        val iterationCount = 10000
        val keyLen = 32
        val keyBytes = PBKDF.pbkdf2("HmacSHA256", password.toByteArray(), saltBytes, iterationCount, keyLen)

        val ivSpec = IvParameterSpec(ivBytes)
        val keySpec = SecretKeySpec(keyBytes, "AES")

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        val encryptedBytes = cipher.doFinal(text.toByteArray())

        return Base64.getEncoder()
            .encodeToString(saltBytes + ivBytes + encryptedBytes)
            .replace("\n", "")
    }

    fun aes256CbcDecrypt(encrypted: String, password: String): String {
        val concatenatedBytes = Base64.getDecoder().decode(encrypted)

        val saltBytes = concatenatedBytes.copyOfRange(0, 16)
        val ivBytes = concatenatedBytes.copyOfRange(16, 32)
        val encryptedBytes = concatenatedBytes.copyOfRange(32, concatenatedBytes.size)

        val iterationCount = 10000
        val keyLen = 32
        val keyBytes = PBKDF.pbkdf2("HmacSHA256", password.toByteArray(), saltBytes, iterationCount, keyLen)

        val ivSpec = IvParameterSpec(ivBytes)
        val keySpec = SecretKeySpec(keyBytes, "AES")

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        val decryptedBytes = cipher.doFinal(encryptedBytes)

        return String(decryptedBytes)
    }

    private fun randomBytes(size: Int): ByteArray {
        val random = Random()
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }
}