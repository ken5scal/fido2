package com.example.kengo.androidfido2

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.design.widget.Snackbar
import android.support.v7.app.AppCompatActivity
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import com.google.android.gms.fido.fido2.Fido2ApiClient
import kotlinx.android.synthetic.main.activity_main.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

private const val provider = "AndroidKeyStore"
// TODO for multi-account case add random number and save it in shared preference?
private const val keyStoreAlias = "FidoAssertionKey"
// TODO erase this later
private const val challenge = "Tf65bS6D5temh2BwvptqgBPb25iZDRxjwC5ans91IIJDrcrOpnWTK4LVgFjeUV4GDMe44w8SI5NsZssIXTUvDg"


class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show()
        }

        val keyStore = KeyStore.getInstance(provider)
        keyStore.load(null)

        // Just for implementing purpose
        keyStore.aliases().iterator().forEach {
            keyStore.deleteEntry(it)
        }

        if (!keyStore.containsAlias(keyStoreAlias)) {
            generateKeyPair(keyStoreAlias, challenge, true, true)
        }

        val certs = keyStore.getCertificateChain(keyStoreAlias)
        val x509Certs: Array<ByteArray?> = arrayOfNulls(certs.size)
        certs.forEachIndexed { index, certificate ->
            x509Certs[index] = certificate.encoded
            Log.d("cert", certificate.toString())
        }

    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }
}


fun generateKeyPair(storeAlias: String, challenge: String, up: Boolean, uv : Boolean): KeyPair {
    // TODO Check pre-requisites for  .setUserAuthenticationRequired(true)
    // KeyguardManager.isDeviceSecure
    // setUserAuthenticationValidityDurationSeconds

    val params = KeyGenParameterSpec.Builder(storeAlias, KeyProperties.PURPOSE_SIGN)
        // TODO
        // For Now, just use ECDSA w/ SHA-256 for algorithm: //For Now, just use ES256
        // According to RFC8152, "it is suggested that SHA-256 be used only with curve P-256"
        // This automatically makes the curve to be 'secp256r1' according to recommendation in RFC5480
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
        // TODO Causes: android.security.KeyStoreException: Not implemented
        //.setUserPresenceRequired(up)
        .setUserAuthenticationRequired(uv)
        .setUserConfirmationRequired(true)
        .setAttestationChallenge(challenge.toByteArray())
        .build()

    val keyPairGenerator = KeyPairGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_EC, provider)
    keyPairGenerator.initialize(params)

    return keyPairGenerator.generateKeyPair()
}

private fun sendRegisterRequestToClient() {
    val fido2Client = Fido2ApiClient()
}