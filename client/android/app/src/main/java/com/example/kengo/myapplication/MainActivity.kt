package com.example.kengo.fido2

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.v7.app.AppCompatActivity
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

val provier = "AndroidKeyStore"
val keyStoreAlias = "FidoAssertionKey"
// TODO erase this later
val challenge = "Tf65bS6D5temh2BwvptqgBPb25iZDRxjwC5ans91IIJDrcrOpnWTK4LVgFjeUV4GDMe44w8SI5NsZssIXTUvDg"

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyStore = KeyStore.getInstance(provier)
        keyStore.load(null)

        if (!keyStore.containsAlias(keyStoreAlias)) {
            generateKeyPair(keyStoreAlias, true, true)
        }

        val certs = keyStore.getCertificateChain(keyStoreAlias)
        val x509Certs: Array<ByteArray?> = arrayOfNulls(certs.size)
        certs.forEachIndexed { index, certificate ->
            x509Certs[index] = certificate.encoded
        }
    }
}

fun generateKeyPair(storeAlias: String, up: Boolean, uv : Boolean): KeyPair {
    val params = KeyGenParameterSpec.Builder(storeAlias, KeyProperties.PURPOSE_SIGN)
        // TODO
        // For Now, just use ECDSA w/ SHA-256 for algorithm: //For Now, just use ES256
        // According to RFC8152, "it is suggested that SHA-256 be used only with curve P-256"
        // This automatically makes the curve to be 'secp256r1' according to recommendation in RFC5480
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserPresenceRequired(up)
        .setUserAuthenticationRequired(uv)
        // TODO: Is for message confirmation when purchasing it
        // FIXME
        .setUserConfirmationRequired(true)
        .setAttestationChallenge(challenge.toByteArray())
        .build()

    val keyPairGenerator = KeyPairGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    keyPairGenerator.initialize(params)

    return keyPairGenerator.generateKeyPair()
}