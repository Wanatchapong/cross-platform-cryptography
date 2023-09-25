<script setup>
import { ref } from 'vue'
import CryptoJS from 'crypto-js'

const inputText = ref('Abc1234')
const inputPassword = ref('MyPassword')

const outputEncrypted = ref('')
const outputDecrypted = ref('')

function aes256CbcEncrypt(text, password) {
  const saltWordArray = CryptoJS.lib.WordArray.random(16) // 16 bytes
  const ivWordArray = CryptoJS.lib.WordArray.random(16) // 16 bytes

  const iterations = 10000
  const keySize = 8 // 256 bits / 8 bytes = 32 bytes (WordArray is 32 bits / 8 bytes = 4 bytes) => 32/4 bytes = 8 bytes
  const key = CryptoJS.PBKDF2(password, saltWordArray, {
    keySize,
    iterations,
    hasher: CryptoJS.algo.SHA256
  })

  const encryptedWordArray = CryptoJS.AES.encrypt(text, key, {
    iv: ivWordArray
  }).ciphertext

  return CryptoJS.lib.WordArray.create()
    .concat(saltWordArray)
    .concat(ivWordArray)
    .concat(encryptedWordArray)
    .toString(CryptoJS.enc.Base64)
}

function aes256CbcDecrypt(encrypted, password) {
  const concatenatedWordArray = CryptoJS.enc.Base64.parse(encrypted)

  const saltWordArray = CryptoJS.lib.WordArray.create(concatenatedWordArray.words.slice(0, 4))
  const ivWordArray = CryptoJS.lib.WordArray.create(concatenatedWordArray.words.slice(4, 8))

  const iterations = 10000
  const keySize = 8
  const key = CryptoJS.PBKDF2(password, saltWordArray, {
    keySize,
    iterations,
    hasher: CryptoJS.algo.SHA256
  })

  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.lib.WordArray.create(concatenatedWordArray.words.slice(8))
  })
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: ivWordArray })
  return decrypted.toString(CryptoJS.enc.Utf8)
}

function doEncryptDecrypt() {
  outputEncrypted.value = aes256CbcEncrypt(inputText.value, inputPassword.value)
  outputDecrypted.value = aes256CbcDecrypt(outputEncrypted.value, inputPassword.value)
}
</script>

<template>
  <div class="cryptography">
    <div class="row">
      <div>Text:</div>
      <input v-model="inputText" />
    </div>

    <div class="row">
      <div>Password:</div>
      <input v-model="inputPassword" />
    </div>

    <div class="row">
      <div></div>
      <button @click="doEncryptDecrypt">Encrypt/Decrypt</button>
    </div>

    <div class="row">
      <div>Encrypted:</div>
      <div>{{ outputEncrypted }}</div>
    </div>

    <div class="row">
      <div>Decrypted:</div>
      <div>{{ outputDecrypted }}</div>
    </div>
  </div>
</template>

<style scoped>
.cryptography {
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.row {
  display: grid;
  grid-template-columns: 120px 200px;
  margin-bottom: 4px;
}
</style>
