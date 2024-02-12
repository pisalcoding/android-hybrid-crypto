

# Android Hybrid Crypto (AES + RSA + SHA + PKI)
[![](https://jitpack.io/v/pisalcoding/android-hybrid-crypto.svg)](https://jitpack.io/#pisalcoding/android-hybrid-crypto)

HybridCrypto is simple customizable Android implementation of hybrid cryptography (AES+RSA+Hash) recommended by [OWASP](https://mobile-security.gitbook.io/mobile-security-testing-guide/general-mobile-app-testing-guide/0x04g-testing-cryptography).

## Usage

> Step 1: Add this your root build.gradle
```java
repositories {  
	...
    maven { url "https://jitpack.io" }
}

```
> Step 2: Add this your app build.gradle
```java
dependencies {
    implementation 'com.github.pisalcoding:hybrid-crypto:x.y.z'
}
```

> Step 3: Initialize HybridCrypto in your main Application or Activity onCreate()
```kotlin
override fun onCreate() {  
    val publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvTtZxoq7IKTwRkADtWix\n" +  
            "Ryv/CHKK+skNlMMV5G+om75HgHUo8AOzHnj9yUvhcm8Maz46ukxiZsvDPgExu9N1\n" +  
            "agEm9HHJEZg1VN+2dT+JojODuC3qkF7o94duchQX44gPjyIBEE/113E6fS51SGGm\n" +  
            "WYrCapSYjNRubB97O1WPm/2nK+A/m9KTtCuIZMp4i/qe4mXCLMRepFO2ORBLD5Ac\n" +  
            "RU+/tF15IruvaBhZezY+IX571yRao3ZLlVBJtZKU7SHp5udxQ0daRxtsVc9aloC3\n" +  
            "TRRL8RvFjHyg7V+uSHkg6cN4IIMrTnkwVkn+7BE9KrT7tY8yEkSE8W4WVCDChIRf\n" +  
            "FwIDAQAB\n"  
  
    HybridCrypto.initialize(HybridCrypto.Configuration.default, publicKey) 
}
```
> Step 4 (Final): Use it wherever you want
```kotlin
HybridCrypto.getInstance()  
        .encrypt("Hello")  
        .let { Log.d("Test", it.httpParams.toString()) }
```

## Result
Once encryption is successful, you'll get a Http-friendly result object
```kotlin
data class HttpFriendlyResult(  
   val requestPassword: String,
   val iv: String,  
   val salt: String,  
   val responsePassword: String,  
   val encryptedData: String,  
   val signature: String,  
)
```
