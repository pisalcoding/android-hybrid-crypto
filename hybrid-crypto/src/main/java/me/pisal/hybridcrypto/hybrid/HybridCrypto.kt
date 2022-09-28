package me.pisal.hybridcrypto.hybrid

import android.util.Base64
import me.pisal.hybridcrypto.aes.AESCipher
import me.pisal.hybridcrypto.rsa.RSACipher
import java.io.Serializable
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * A combined crypto mechanism of
 * AES + RSA + Hashing
 */
class HybridCrypto private constructor() {

    private var mConfiguration: Configuration = Configuration.default
    private lateinit var mPlainPublicKey: String

    private val mAESCipher by lazy {
        AESCipher(
            mConfiguration.aesKeySize,
            mConfiguration.aesMode,
            mConfiguration.aesKeyIterationCount
        )
    }

    private val mRSACipher by lazy {
        RSACipher(
            mPlainPublicKey,
            mConfiguration.rsaMode
        )
    }

    fun encrypt(
        message: String
    ): HybridCipherResult {
        if (!::mPlainPublicKey.isInitialized) {
            throw Exception("Public key is not provided! Make sure you called initialize().")
        }

        // AES operation
        val requestKey = generateRandomAESPassword()
        val responseKey = generateRandomAESPassword()
        val aesObj = mAESCipher.encrypt(requestKey, message)
        System.gc()

        // SHA512 Signature
        val signature = mRSACipher.encrypt(sha512(message))

        // RSA
        val params = HttpFriendlyResult(
            requestPassword = mRSACipher.encrypt(requestKey),
            iv = mRSACipher.encrypt(aesObj.iv),
            salt = mRSACipher.encrypt(aesObj.salt),
            responsePassword = mRSACipher.encrypt(responseKey),
            signature = signature,
            encryptedData = aesObj.encodedData
        )
        return HybridCipherResult(responseKey, params)
    }

    private fun generateRandomAESPassword(): String {
        val keyBytes = ByteArray(mConfiguration.aesKeySize)
        SecureRandom().nextBytes(keyBytes)
        return Base64.encodeToString(keyBytes, Base64.NO_WRAP)
    }

    private fun sha512(message: String): String {
        val bytes = message.toByteArray()
        val md = MessageDigest.getInstance("SHA-512")
        val digest = md.digest(bytes)
        return digest.fold("") { str, it -> str + "%02x".format(it) }

//        val bytes = input.toByteArray()
//        val md = MessageDigest.getInstance("SHA-512")
//        val digest = md.digest(bytes)
//        return digest.fold("") { str, it -> str + "%02x".format(it) }
//        val md = MessageDigest.getInstance("SHA-512")
//        val digest = md.digest(message.toByteArray())
//        val builder = StringBuilder()
//        for (i in digest.indices) {
//            builder.append(((digest[i] and 0xff.toByte()) + 0x100)
//                .toString(16)
//                .substring(1))
//        }
//        return builder.toString()
    }

    data class Configuration(
        var aesKeySize: Int,
        var aesMode: String,
        var aesKeyIterationCount: Int,
        var rsaMode: String,
    ): Serializable {
        companion object {
            val default = Configuration(
                DEFAULT_AES_KEY_SIZE,
                DEFAULT_AES_MODE,
                DEFAULT_AES_KEY_ITERATION_COUNT,
                DEFAULT_RSA_MODE
            )
        }
    }

    companion object {
        private const val DEFAULT_AES_KEY_SIZE = 16 // Bytes
        private const val DEFAULT_AES_KEY_ITERATION_COUNT = 100 // Rounds
        private const val DEFAULT_RSA_MODE = "RSA/None/PKCS1Padding"
        private const val DEFAULT_AES_MODE = "AES/CBC/PKCS7Padding"

        private lateinit var instance: HybridCrypto

        /**
         * Should be called in Application's onCreate() to initialize the library.
         *
         * @param configuration: your own configuration.
         * Without calling this method, default configuration is applied.
         *
         * @param publicKey: RSA public key plain base64 string.
         * Don't include the "BEGIN || END PUBLIC KEY".
         * Example:
         * ```MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxKqA6G/84+ZhSwt59NVK
         * wr3qaTJHEQ339r+QG/tyqPprWHm5Qn0J3cECznt1/paxcBMqNvIF70MmZZYRZFiK
         * 5HlgeKL2xwtaB1wDs2NBOnptNfARPvOEiAfvAb6ybCMQ/k+VUIBUw/Cn1TM8iogS
         * clJHwzt8PEq0GtDrIgkEsqWrjth7HozvqRcNsrCzJ+OEkGVTIgVh2fsUBReg/rGs
         * CF6at//I6zEhP70V/We+9fD5oQ+/R6E8jgxM54CPbilUZe/buJwUq5I088K+Bw4g
         * 06Gd2E2QeegIGzNrQ1ynUaHa9myPNsUnwLR8DH488dWFdIKLJ4gA3L5bGsMg48I9
         * cwIDAQAB```
         */
        fun initialize(configuration: Configuration, publicKey: String) {
            getInstance().mPlainPublicKey = publicKey
            getInstance().mConfiguration = configuration
        }

        fun getInstance(): HybridCrypto {
            if (!::instance.isInitialized) {
                instance = HybridCrypto()
            }
            return instance
        }
    }
}