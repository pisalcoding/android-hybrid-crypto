package me.pisal.hybridcrypto.hybrid

data class HttpFriendlyResult(
    /**
     * RSA-encrypted AES password of request body
     */
    val requestPassword: String,

    /**
     * IV that was used while encrypting the raw data
     */
    val iv: String,

    /**
     * salt that was used while encrypting the raw data
     */
    val salt: String,

    /**
     * RSA-encrypted AES password for peer/server to encrypt the response
     */
    val responsePassword: String,

    /**
     * AES-encrypted data
     */
    val encryptedData: String,

    /**
     * RSA-encrypted SHA512 hash of the raw data
     */
    val signature: String,
)