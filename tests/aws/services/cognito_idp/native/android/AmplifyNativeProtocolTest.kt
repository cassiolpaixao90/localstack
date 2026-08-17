package localstack.cognito.nativegate

import android.content.Context
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import com.amplifyframework.api.aws.AWSApiPlugin
import com.amplifyframework.api.rest.RestOptions
import com.amplifyframework.auth.cognito.AWSCognitoAuthPlugin
import com.amplifyframework.auth.cognito.AWSCognitoAuthSession
import com.amplifyframework.auth.cognito.options.AuthFlowType
import com.amplifyframework.auth.cognito.options.AWSCognitoAuthSignInOptions
import com.amplifyframework.auth.cognito.result.AWSCognitoAuthSignOutResult
import com.amplifyframework.auth.options.AuthFetchSessionOptions
import com.amplifyframework.auth.options.AuthSignOutOptions
import com.amplifyframework.auth.result.step.AuthSignInStep
import com.amplifyframework.core.Amplify
import com.amplifyframework.core.AmplifyConfiguration
import com.amplifyframework.kotlin.auth.KotlinAuthFacade
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.Security
import java.security.cert.Certificate
import java.time.Instant
import java.util.Base64
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.CompletableFuture
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AmplifyNativeProtocolTest {
    private val authPlugin = AWSCognitoAuthPlugin()
    private val auth = KotlinAuthFacade()

    @Test
    fun realAmplifyAndroidProtocol() {
        stage("test-entered")
        val protocol = CompletableFuture.runAsync {
            runBlocking {
                withTimeout(90_000) {
                    val environment = requiredEnvironment()
                    stage("environment-loaded")
                    val context = ApplicationProvider.getApplicationContext<Context>()
                    installRobolectricKeyStoreAdapter()
                    Amplify.addPlugin(authPlugin)
                    Amplify.addPlugin(AWSApiPlugin())
                    stage("plugins-added")
                    Amplify.configure(configuration(environment), context)
                    stage("amplify-configured")

            val signInOptions = AWSCognitoAuthSignInOptions.builder()
                .authFlowType(AuthFlowType.USER_SRP_AUTH)
                .build()
            stage("sign-in-started")
            val started = auth.signIn(environment.username, environment.temporaryPassword, signInOptions)
            stage("sign-in-returned")
            assertEquals(AuthSignInStep.CONFIRM_SIGN_IN_WITH_NEW_PASSWORD, started.nextStep.signInStep)
            assertTrue(auth.confirmSignIn(environment.newPassword).isSignedIn)

            val setup = auth.setUpTOTP()
            auth.verifyTOTPSetup(totp(setup.sharedSecret))
            suspendCoroutine<Unit> { continuation ->
                authPlugin.updateMFAPreference(
                    null,
                    com.amplifyframework.auth.cognito.MFAPreference.PREFERRED,
                    null,
                    { continuation.resume(Unit) },
                    { continuation.resumeWithException(it) },
                )
            }

            val initial = auth.fetchAuthSession() as AWSCognitoAuthSession
            val initialTokens = requireNotNull(initial.userPoolTokensResult.value)
            val claims = claims(requireNotNull(initialTokens.idToken))
            assertEquals(environment.clientId, claims.getString("aud"))
            assertEquals(environment.tenantId, claims.getString("custom:tenantId"))
            assertEquals(listOf("trainer"), claims.getJSONArray("cognito:groups").strings())

            val refreshOptions = AuthFetchSessionOptions.builder().forceRefresh(true).build()
            val refreshed = auth.fetchAuthSession(refreshOptions) as AWSCognitoAuthSession
            val refreshedTokens = requireNotNull(refreshed.userPoolTokensResult.value)
            assertNotEquals(initialTokens.accessToken, refreshedTokens.accessToken)

            val apiResponse = suspendCoroutine<String> { continuation ->
                val request = RestOptions.builder()
                    .addPath("/v1/profile")
                    .addHeader("Authorization", "Bearer ${refreshedTokens.idToken}")
                    .build()
                Amplify.API.get(
                    "billgym",
                    request,
                    { continuation.resume(String(it.data.rawBytes)) },
                    { continuation.resumeWithException(it) },
                )
            }
            assertEquals("ok", JSONObject(apiResponse).getString("status"))

            val global = AuthSignOutOptions.builder().globalSignOut(true).build()
            val signedOut = auth.signOut(global)
            assertTrue(signedOut is AWSCognitoAuthSignOutResult.CompleteSignOut)
            assertFalse(auth.fetchAuthSession().isSignedIn)

            val second = auth.signIn(environment.username, environment.newPassword, signInOptions)
            assertEquals(AuthSignInStep.CONFIRM_SIGN_IN_WITH_TOTP_CODE, second.nextStep.signInStep)
            assertTrue(auth.confirmSignIn(totp(setup.sharedSecret)).isSignedIn)
            assertTrue(auth.signOut(global) is AWSCognitoAuthSignOutResult.CompleteSignOut)

                    File(environment.evidenceFile).writeText(
                        JSONObject()
                            .put("apiStatus", "ok")
                            .put("globalSignOut", true)
                            .put("groups", JSONArray(listOf("trainer")))
                            .put("newPassword", true)
                            .put("refresh", true)
                            .put("robolectricKeyStoreAliases", 0)
                            .put("robolectricKeyStoreProviderClass", TestOwnedLegacyKeyStoreProvider::class.java.name)
                            .put("robolectricKeyStoreProviderName", "LocalStackRobolectricAndroidKeyStore")
                            .put("robolectricKeyStoreWritesRejected", true)
                            .put("sdk", "Amplify Android 2.39.0")
                            .put("tenantId", environment.tenantId)
                            .put("totp", true)
                            .toString(),
                    )
                }
            }
        }
        val deadline = System.nanoTime() + 100_000_000_000
        while (!protocol.isDone) {
            shadowOf(Looper.getMainLooper()).idle()
            check(System.nanoTime() < deadline) { "Android main looper deadline exceeded" }
            Thread.sleep(5)
        }
        protocol.join()
    }

    private fun configuration(environment: Environment): AmplifyConfiguration {
        val authPluginConfiguration = JSONObject()
            .put(
                "CognitoUserPool",
                JSONObject().put(
                    "Default",
                    JSONObject()
                        .put("PoolId", environment.poolId)
                        .put("AppClientId", environment.clientId)
                        .put("Region", environment.region)
                        .put("Endpoint", environment.cognitoHost),
                ),
            )
            .put(
                "Auth",
                JSONObject().put(
                    "Default",
                    JSONObject().put("authenticationFlowType", "USER_SRP_AUTH"),
                ),
            )
        val apiPluginConfiguration = JSONObject().put(
            "billgym",
            JSONObject()
                .put("endpoint", environment.apiEndpoint)
                .put("endpointType", "REST")
                .put("authorizationType", "NONE")
                .put("region", environment.region),
        )
        return AmplifyConfiguration.fromJson(
            JSONObject()
                .put("auth", JSONObject().put("plugins", JSONObject().put("awsCognitoAuthPlugin", authPluginConfiguration)))
                .put("api", JSONObject().put("plugins", JSONObject().put("awsAPIPlugin", apiPluginConfiguration))),
        )
    }

    private fun requiredEnvironment() = Environment(
        apiEndpoint = required("AMPLIFY_ANDROID_API_ENDPOINT"),
        clientId = required("AMPLIFY_ANDROID_CLIENT_ID"),
        cognitoHost = required("AMPLIFY_ANDROID_COGNITO_HOST"),
        evidenceFile = required("AMPLIFY_ANDROID_EVIDENCE_FILE"),
        newPassword = required("AMPLIFY_ANDROID_NEW_PASSWORD"),
        poolId = required("AMPLIFY_ANDROID_POOL_ID"),
        region = required("AMPLIFY_ANDROID_REGION"),
        temporaryPassword = required("AMPLIFY_ANDROID_TEMPORARY_PASSWORD"),
        tenantId = required("AMPLIFY_ANDROID_TENANT_ID"),
        username = required("AMPLIFY_ANDROID_USERNAME"),
    )

    private fun required(name: String): String = requireNotNull(System.getenv(name)) {
        "missing native gate environment: $name"
    }.also { require(it.isNotBlank() && it.length <= 2048) }

    private fun installRobolectricKeyStoreAdapter() {
        check(Security.getProviders("KeyStore.AndroidKeyStore").isNullOrEmpty()) {
            "Robolectric unexpectedly supplied AndroidKeyStore"
        }
        Security.insertProviderAt(TestOwnedLegacyKeyStoreProvider(), 1)
        check(Security.getProviders("KeyStore.AndroidKeyStore")?.size == 1)
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        check(keyStore.size() == 0 && !keyStore.aliases().hasMoreElements())
        check(
            runCatching {
                keyStore.setKeyEntry("write-must-fail", byteArrayOf(1), emptyArray())
            }.isFailure,
        )
    }

    private fun stage(value: String) {
        System.getenv("AMPLIFY_ANDROID_EVIDENCE_FILE")?.let { path ->
            File(path).writeText(JSONObject().put("stage", value).toString())
        }
    }

    private fun claims(token: String): JSONObject {
        val parts = token.split('.')
        require(parts.size == 3)
        return JSONObject(String(Base64.getUrlDecoder().decode(parts[1])))
    }

    private fun totp(secret: String): String {
        val counter = Instant.now().epochSecond / 30
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(base32(secret), "HmacSHA1"))
        val digest = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        val offset = digest.last().toInt() and 0x0f
        val number = ByteBuffer.wrap(digest, offset, 4).int and 0x7fff_ffff
        return (number % 1_000_000).toString().padStart(6, '0')
    }

    private fun base32(value: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var accumulator = 0
        var bits = 0
        val output = ArrayList<Byte>()
        value.uppercase().filter { it != '=' }.forEach { character ->
            val index = alphabet.indexOf(character)
            require(index >= 0)
            accumulator = (accumulator shl 5) or index
            bits += 5
            if (bits >= 8) {
                bits -= 8
                output.add(((accumulator shr bits) and 0xff).toByte())
            }
        }
        return output.toByteArray()
    }

    private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)

    private data class Environment(
        val apiEndpoint: String,
        val clientId: String,
        val cognitoHost: String,
        val evidenceFile: String,
        val newPassword: String,
        val poolId: String,
        val region: String,
        val temporaryPassword: String,
        val tenantId: String,
        val username: String,
    )
}

class TestOwnedLegacyKeyStoreProvider : Provider(
    "LocalStackRobolectricAndroidKeyStore",
    1.0,
    "Read-empty AndroidKeyStore adapter for Amplify legacy migration under Robolectric",
) {
    init {
        put("KeyStore.AndroidKeyStore", TestOwnedLegacyKeyStoreSpi::class.java.name)
    }
}

class TestOwnedLegacyKeyStoreSpi : KeyStoreSpi() {
    override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
    override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
    override fun engineAliases(): Enumeration<String> = Collections.emptyEnumeration()
    override fun engineContainsAlias(alias: String?) = false
    override fun engineSize() = 0
    override fun engineIsKeyEntry(alias: String?) = false
    override fun engineIsCertificateEntry(alias: String?) = false
    override fun engineGetKey(alias: String?, password: CharArray?): Key? = null
    override fun engineGetCertificateChain(alias: String?): Array<Certificate>? = null
    override fun engineGetCertificate(alias: String?): Certificate? = null
    override fun engineGetCreationDate(alias: String?): Date? = null
    override fun engineGetCertificateAlias(certificate: Certificate?): String? = null
    override fun engineDeleteEntry(alias: String?) = Unit

    override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<Certificate>?) {
        error("legacy AndroidKeyStore adapter is read-empty only")
    }

    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<Certificate>?) {
        error("legacy AndroidKeyStore adapter is read-empty only")
    }

    override fun engineSetCertificateEntry(alias: String?, certificate: Certificate?) {
        error("legacy AndroidKeyStore adapter is read-empty only")
    }
}
