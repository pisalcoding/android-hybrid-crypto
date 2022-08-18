package me.pisal.hybridencryption

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import me.pisal.hybridcrypto.hybrid.HybridCrypto

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        demo()
    }

    private fun demo() {
        val publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvTtZxoq7IKTwRkADtWix\n" +
                "Ryv/CHKK+skNlMMV5G+om75HgHUo8AOzHnj9yUvhcm8Maz46ukxiZsvDPgExu9N1\n" +
                "agEm9HHJEZg1VN+2dT+JojODuC3qkF7o94duchQX44gPjyIBEE/113E6fS51SGGm\n" +
                "WYrCapSYjNRubB97O1WPm/2nK+A/m9KTtCuIZMp4i/qe4mXCLMRepFO2ORBLD5Ac\n" +
                "RU+/tF15IruvaBhZezY+IX571yRao3ZLlVBJtZKU7SHp5udxQ0daRxtsVc9aloC3\n" +
                "TRRL8RvFjHyg7V+uSHkg6cN4IIMrTnkwVkn+7BE9KrT7tY8yEkSE8W4WVCDChIRf\n" +
                "FwIDAQAB\n"

        HybridCrypto.initialize(HybridCrypto.Configuration.default, publicKey)

        HybridCrypto.getInstance()
            .encrypt("Hello")
            .let { Log.d("Test", it.httpParams.toString()) }
    }
}