package org.draken.usagi.core.network

import android.annotation.SuppressLint
import android.content.Context
import android.content.res.AssetManager
import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import org.draken.usagi.BuildConfig
import org.draken.usagi.core.util.ext.printStackTraceDebug
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

private val trustAllSslFactory: Pair<SSLSocketFactory, X509TrustManager> by lazy {
	val trustAllCerts =
		object : X509TrustManager {
			override fun checkClientTrusted(
				chain: Array<X509Certificate>,
				authType: String,
			) = Unit

			override fun checkServerTrusted(
				chain: Array<X509Certificate>,
				authType: String,
			) = Unit

			override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
		}
	val sslContext = SSLContext.getInstance("SSL")
	sslContext.init(null, arrayOf(trustAllCerts), SecureRandom())
	sslContext.socketFactory to trustAllCerts
}

@SuppressLint("CustomX509TrustManager")
fun OkHttpClient.Builder.disableCertificateVerification() =
	also { builder ->
		runCatching {
			val (factory, trustManager) = trustAllSslFactory
			builder.sslSocketFactory(factory, trustManager)
			builder.hostnameVerifier { _, _ -> true }
		}.onFailure {
			it.printStackTraceDebug()
		}
	}

private var extraCertificates: HandshakeCertificates? = null

fun OkHttpClient.Builder.installExtraCertificates(context: Context) =
	also { builder ->
		val certificates =
			extraCertificates ?: run {
				val certificatesBuilder =
					HandshakeCertificates
						.Builder()
						.addPlatformTrustedCertificates()
				val assets = context.assets.list("").orEmpty()
				for (path in assets) {
					if (path.endsWith(".pem")) {
						val cert = loadCert(context, path) ?: continue
						certificatesBuilder.addTrustedCertificate(cert)
					}
				}
				certificatesBuilder.build().also { extraCertificates = it }
			}
		builder.sslSocketFactory(certificates.sslSocketFactory(), certificates.trustManager)
	}

private fun loadCert(
	context: Context,
	path: String,
): X509Certificate? =
	runCatching {
		val cf = CertificateFactory.getInstance("X.509")
		context.assets.open(path, AssetManager.ACCESS_STREAMING).use {
			cf.generateCertificate(it)
		} as X509Certificate
	}.onFailure { e ->
		e.printStackTraceDebug()
	}.onSuccess {
		if (BuildConfig.DEBUG) {
			Log.i("ExtraCerts", "Loaded cert $path")
		}
	}.getOrNull()
