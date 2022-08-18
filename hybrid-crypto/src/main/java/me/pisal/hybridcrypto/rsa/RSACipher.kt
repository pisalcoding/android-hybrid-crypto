package me.pisal.hybridcrypto.rsa

import android.util.Base64
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class RSACipher(
    private val plainPublicKey: String,
    private val rsaMode: String = "RSA/None/PKCS1Padding"
) {

    private val mPublicKey by lazy { getServerPublicKey() }
    private val mCipher by lazy { getCipher() }

    /**
     * Encrypt plain text with RSA and encode the encrypted with Base64.
     * The RSA public key is server's public key
     */
    fun encrypt(content: String): String {
        val encryptedBytes = mCipher.doFinal(content.encodeToByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    /////////////////////////////////////////
    //#region Private methods
    /////////////////////////////////////////
    private fun getCipher(): Cipher {
        return Cipher.getInstance(rsaMode).apply {
            init(Cipher.ENCRYPT_MODE, mPublicKey)
        }
    }

    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class
    )
    private fun getServerPublicKey(): PublicKey {
        // In the future, if server changes its public key, replace it here
        // Don't include the "BEGIN || END PUBLIC KEY"
        val keyBytes = Base64.decode(plainPublicKey, Base64.DEFAULT)
        val keySpec = X509EncodedKeySpec(keyBytes)
        return KeyFactory
            .getInstance("RSA")
            .generatePublic(keySpec)
    }
    //#endregion
}