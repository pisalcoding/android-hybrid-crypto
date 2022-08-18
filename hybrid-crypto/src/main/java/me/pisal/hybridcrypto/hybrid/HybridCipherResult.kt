package me.pisal.hybridcrypto.hybrid

import java.io.Serializable

data class HybridCipherResult(
    /**
     * Should be saved for decrypting the encrypted response from server
     */
    val rawResponsePassword: String,

    /**
     * Suitable for sending to server via REST API
     */
    val httpParams: HttpFriendlyResult
): Serializable