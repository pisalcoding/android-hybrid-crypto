package me.pisal.hybridcrypto.aes

import android.util.Base64
import java.io.UnsupportedEncodingException
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class AESCipher(
    /**
     * Recommended by OWASP: 16 (bytes)
     */
    private val aesKeySizeInBytes: Int,

    /**
     * Recommended by OWASP: "AES/CBC/PKCS7Padding"
     */
    private val aesMode: String = "AES/CBC/PKCS7Padding",

    /**
     * Recommended: 100 good an equilibrium between robustness and performance.
     * The bigger, the more secure, but slower at the same time.
     */
    private val keyIterationCount: Int = 100
) {

    @Throws(
        UnsupportedEncodingException::class,
        GeneralSecurityException::class,
        NoSuchAlgorithmException::class,
        InvalidKeySpecException::class
    )
    fun encrypt(password: String, message: String): AESResult {
        val ivBytes = ByteArray(16)
        val saltBytes = ByteArray(8)
        SecureRandom().nextBytes(saltBytes)
        SecureRandom().nextBytes(ivBytes)
        val key = generateKeyPassword(
            password = password.toCharArray(),
            salt = saltBytes
        )

        val cipherText = encrypt(
            key = key,
            iv = ivBytes,
            message = message.toByteArray(CHARSET)
        )

        return AESResult(
            salt = Base64.encodeToString(saltBytes, Base64.NO_WRAP),
            iv = Base64.encodeToString(ivBytes, Base64.NO_WRAP),
            encodedData = Base64.encodeToString(cipherText, Base64.NO_WRAP)
        )
    }

    @Throws(
        UnsupportedEncodingException::class,
        GeneralSecurityException::class,
        NoSuchAlgorithmException::class,
        InvalidKeySpecException::class
    )
    fun decrypt(
        password: String,
        salt: String,
        iv: String,
        base64CipherText: String
    ): String {
        val key = generateKeyPassword(
            password = password.toCharArray(),
            salt = Base64.decode(salt, Base64.NO_WRAP)
        )
        val decryptedBytes = decrypt(
            key = key,
            iv = Base64.decode(iv, Base64.NO_WRAP),
            decodedCipherText = Base64.decode(base64CipherText, Base64.NO_WRAP)
        )
        return String(decryptedBytes, CHARSET)
    }

    /////////////////////////////////////////
    //#region Private part for general AES
    /////////////////////////////////////////
    /**
     * More flexible AES encrypt that doesn't encode
     * @param key AES key typically 128, 192 or 256 bit
     * @param iv Initiation Vector
     * @param message in bytes (assumed it's already been decoded)
     * @return Encrypted cipher text (not encoded)
     * @throws GeneralSecurityException if something goes wrong during encryption
     */
    @Throws(GeneralSecurityException::class)
    private fun encrypt(
        key: SecretKeySpec,
        iv: ByteArray,
        message: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance(aesMode)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        return cipher.doFinal(message)
    }

    /**
     * More flexible AES decrypt that doesn't encode
     *
     * @param key AES key typically 128, 192 or 256 bit
     * @param iv Initiation Vector
     * @param decodedCipherText in bytes (assumed it's already been decoded)
     * @return Decrypted message cipher text (not encoded)
     * @throws GeneralSecurityException if something goes wrong during encryption
     */
    @Throws(GeneralSecurityException::class)
    private fun decrypt(
        key: SecretKeySpec,
        iv: ByteArray,
        decodedCipherText: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance(aesMode)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
        return cipher.doFinal(decodedCipherText)
    }

    @Throws(
        NoSuchAlgorithmException::class,
        InvalidKeySpecException::class
    )
    private fun generateKeyPassword(
        password: CharArray,
        salt: ByteArray
    ): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA1")
        val pbeKeySpec = PBEKeySpec(password, salt, keyIterationCount, aesKeySizeInBytes * 8)
        val secretKey = factory.generateSecret(pbeKeySpec)
        return SecretKeySpec(secretKey.encoded, "AES")
    }

    companion object {
        private val CHARSET = Charsets.UTF_8
    }
    //#endregion
}