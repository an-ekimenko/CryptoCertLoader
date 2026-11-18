package my;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyStoreManager {
	
	private static final Logger logger = LogManager.getLogger(KeyStoreManager.class);
	private static final String PASSWORD = "changeit";
	
	// ==========================================
	// SSLCONTEXT MANAGEMENT IN MEMORY
	// ==========================================
	private static SSLContext currentSslContext;

	static {
		// Primary initialization by the standard JVM context at the start of the application.
		try {
			logger.info("Performing primary systemic fallback initialization for active memory SSLContext profile.");
			currentSslContext = SSLContext.getDefault();
		} catch (Exception e) {
			logger.fatal("Failed to perform base system baseline handshake profile definitions initialization.", e);
			throw new RuntimeException("Failed to initialize default SSLContext", e);
		}
	}

	/**
	 * A getter for obtaining the current SSLContext (called from Apache HttpClient).
	 */
	public static SSLContext getSSLContext() {
		logger.debug("Supplying current memory resident reference of the system SSLContext.");
		return currentSslContext;
	}

	/**
	 * Reads the cacerts file from the disk and updates the SSLContext in memory on the fly.
	 */
	public static void refreshSSLContext() {
		logger.info("Executing operational routine sequence to hot-reload local keystore artifacts into JVM memory.");
		try {
			File cacertsFile = getCacertsFile();
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

			try (InputStream is = new FileInputStream(cacertsFile)) {
				keyStore.load(is, PASSWORD.toCharArray());
			}
			logger.debug("Successfully loaded live operational definitions profile from file: {}", cacertsFile.getAbsolutePath());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keyStore);

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());

			currentSslContext = sslContext;
			System.out.println("SSLContext in memory has been successfully refreshed with updated certificates.");
			logger.info("Memory resident application runtime SSLContext re-mapped successfully to the updated system certificates layout.");
		} catch (Exception e) {
			System.err.println("Failed to refresh SSLContext in memory: " + e.getMessage());
			logger.error("Catastrophic runtime exception encountered while building active memory resident cryptographic context.", e);
			e.printStackTrace();
		}
	}

	/**
	 * A helper method for searching for the cacerts file on the disk [Java 8 and Java 9+].
	 */
	private static File getCacertsFile() throws IOException {
		String javaHome = System.getProperty("java.home");
		File cacerts = new File(javaHome, "lib/security/cacerts"); // Java 8
		if (!cacerts.exists()) {
			cacerts = new File(javaHome, "conf/security/cacerts"); // Java 9+
		}
		if (!cacerts.exists()) {
			logger.error("The master system file container 'cacerts' could not be resolved within the local environment paths.");
			throw new IOException("The cacerts file was not found in the JDK/JRE directories.");
		}
		return cacerts;
	}

	/** 
	 * The method intercepts the array of certificates directly from the SSL-Handshake.
	 * 
	 * Rem
	 * When connecting to https://... we can intercept the certificate chain that the server 
	 * sends for encryption. 
	 * 
	 * @param downloadUrl - server URL
	 * @param credentials - Login:password for Basic or the token itself for Token-based authentication.
	 * @param authType - Authentication type ["BASIC", "TOKEN" or "NONE"]
	 */
	public static Collection<? extends Certificate> downloadRemoteCertificates(
			String downloadUrl, 
			String credentials, 
			String authType) throws IOException, InterruptedException, CertificateException 
	{
		logger.info("Initiating dynamic remote handshake sequence to capture raw certificate headers from target: {}", downloadUrl);
		/**
		 * In serverCertificatesRef we will intercept the certificates that the server sends when you connect to it.
		 */
		final AtomicReference<X509Certificate[]> serverCertificatesRef = new AtomicReference<>();

		try {
			/**
			 * Сreate a TrustManager that temporarily trusts all certificates [in order to download new ones].
			 */
			TrustManager[] trustAllCerts = new TrustManager[]{
			        new X509TrustManager() {
			            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
			            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
			            public void checkServerTrusted(X509Certificate[] certs, String authType) {
			                // Safely intercept and extract the remote certificate chain
			                serverCertificatesRef.set(certs);
			            }
			        }
			};

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, trustAllCerts, new SecureRandom());

			// Disable hostname validation in case the server’s domain/IP address does not match.          
			System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
			logger.debug("Internal hostname validation checks bypassed inside the network probe engine loop.");

			HttpClient client = HttpClient.newBuilder()
					.followRedirects(HttpClient.Redirect.ALWAYS)
					.sslContext(sslContext)
					.build();

			// Constructing an HTTP request.
			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
					.uri(URI.create(downloadUrl))
					.GET();
			
			/**
			 * Integration of the authorization type into the request headers [Protection against 401/403 errors].
			 * 
			 * Rem
			 * Some servers or proxy servers [for example, API gateways] are configured in such a way 
			 * that they reset the network connection even before the SSL handshake is completed 
			 * if there is no authorization header in the request at all.
			 */
			if (authType != null) {
				String upperAuthType = authType.trim().toUpperCase();
				
				if ("BASIC".equals(upperAuthType) && credentials != null ) {
					String encodedAuth = Base64.getEncoder().encodeToString(credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
					requestBuilder.header("Authorization", "Basic " + encodedAuth);
					System.out.println("SSL Interception - the Basic Auth header is applied.");
					logger.debug("Basic Auth authentication mapping metadata populated inside the probe context headers.");
					
				} else if (("TOKEN".equals(upperAuthType) || "BEARER".equals(upperAuthType)) && credentials != null) {
					// If the type is TOKEN, then the token itself is passed in the credentials parameter.
					requestBuilder.header("Authorization", "Bearer " + credentials);
					System.out.println("SSL Interception - the Token Auth header is applied.");
					logger.debug("Bearer validation token metrics populated inside the probe context headers.");
				}
			}
			
			HttpRequest request = requestBuilder.build();

			/**
			 * Send the request. It doesn’t matter what the server returns — at the moment of connection, 
			 * checkServerTrusted will run and place the certificates in interceptedCerts.
			 */
			client.send(request, HttpResponse.BodyHandlers.discarding()); 

			X509Certificate[] interceptedCerts = serverCertificatesRef.get();
			
			if (interceptedCerts != null && interceptedCerts.length > 0) {
				logger.info("Successfully completed handshake intercept capture routine. Retained a collection of {} items.", interceptedCerts.length);
				// Return the chain intercepted from the network as a collection.
				return Arrays.asList(interceptedCerts);
			} else {
				logger.error("The network socket pipeline successfully processed the validation probe but captured no valid certificate bodies.");
				throw new IOException("Failed to intercept SSL certificates during the connection.");
			}

		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			logger.error("Internal cryptography initialization fault occurred during the execution of network interception hooks.", e);
			throw new IOException("SSL initialization error for interception - " + e.getMessage(), e);
		}
	}

	/**
	 * Сheck the certificates chain for the specified URL within cacerts and update it if necessary.
	 * 
	 * @param downloadUrl - server URL
	 * @param credentials - Login:password for Basic or the token itself for Token-based authentication.
	 * @param authType Authentication type ["BASIC", "TOKEN", or "NONE"]
	 */
	public static void checkAndDownloadCertificateChain(
			String downloadUrl, 
			String credentials, 
			String authType) 
	{
		logger.info("Invoking scheduled cryptographic audit cycle sequence for master file container validation.");
		try {
			// 1 - Download the current certificate chain from the server, taking into account the authorization type.
			Collection<? extends java.security.cert.Certificate> remoteCerts = 
					downloadRemoteCertificates(downloadUrl, credentials, authType);
			System.out.println("The chain has been successfully intercepted; \n"
								+ remoteCerts.size() + " certificates have been found.");

			// 2 - Loading the current system storage cacerts.
			File cacertsFile = getCacertsFile();
			logger.debug("Binding to disk physical environment endpoint tracking target path: {}", 
					cacertsFile.getAbsolutePath());
			
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			try (InputStream is = new FileInputStream(cacertsFile)) {
				keyStore.load(is, PASSWORD.toCharArray());
			}
			System.out.println("The current system storage cacerts were loaded.");
			logger.info("Master keystore database successfully mapped and instantiated into execution context.");
			
			boolean isUpdatedNeeded = false;
			Date now = new Date();
			
			// 3 - Check each downloaded certificate within our cacerts.
			for (java.security.cert.Certificate cert : remoteCerts) {
				if (cert instanceof X509Certificate) {
					X509Certificate remoteCert = (X509Certificate) cert;
					/* X500Principal - the "passport data" of the certificate owner or the entity that issued the certificate.
					 * 	Subject - to whom the certificate was issued; Issuer - who issued and signed this certificate.
					 */
					X500Principal subject = remoteCert.getSubjectX500Principal();
					
					// Generate a unique alias for storage in KeyStore based on the subject’s hash.
					String alias = "auto_generated_" + Math.abs(subject.getName().hashCode());

					// Check whether such a certificate already exists in cacerts.
					if (keyStore.containsAlias(alias)) {
						java.security.cert.Certificate localCert = keyStore.getCertificate(alias);
						if (localCert instanceof X509Certificate) {
							X509Certificate x509Local = (X509Certificate) localCert;
							try {
								// Check whether the local certificate is outdated.
								x509Local.checkValidity(now);
								System.out.println("Certificate [" + subject.getName() + "] is already in cacerts and is valid.");
								logger.info("Storage validation lookup successful: mapping key '{}' points to a fully "
										+ "valid signature entry.",	alias);
							} catch (CertificateException e) {
								// The local certificate is outdated - we’re overwriting it with a new one.
								System.out.println("The certificate " + subject.getName() +
										" in cacerts is outdated -> we are updating it.");
								logger.warn("Storage item verification warning: mapping key '{}' contains an outdated identity. "
										+ "Scheduling synchronization update.", alias);
								keyStore.setCertificateEntry(alias, remoteCert);
								isUpdatedNeeded = true;
							}
						}
					} else {
						// If such a certificate is not in the repository at all, we add it.
						System.out.println("The new certificate "  + subject.getName()
											+ "has been detected -> adding it to cacerts.");
						logger.info("Unmapped certificate signature discovered on target endpoint. "
								+ "Assigning entry identifier key '{}' to storage index.", alias);
						keyStore.setCertificateEntry(alias, remoteCert);
						isUpdatedNeeded = true;
					}
				}
			}
			// 4 - If changes are detected, create a secure backup and commit updates to disk
			if (isUpdatedNeeded) {
				try {
					// Generate a distinct backup filename using a precise timestamp pattern
					String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
					File backupFile = new File(cacertsFile.getParent(), "cacerts.backup_" + timestamp);
				
					// Execute proactive backup copy, replacing any existing asset with the same namespace
					Files.copy(cacertsFile.toPath(), backupFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
					System.out.println("A backup copy " + backupFile.getAbsolutePath()
									+ " of cacerts has been created.");
					logger.info("Safety check environmental recovery snapshot file written to: {}", backupFile.getAbsolutePath());
					// Commit the modified KeyStore state to the primary systemic cacerts file
					try (FileOutputStream fos = new FileOutputStream(cacertsFile)) {
						keyStore.store(fos, PASSWORD.toCharArray());
					}
					System.out.println("The cacerts file has been successfully updated on the disk.");
					logger.info("Transaction finalized: active state structural modifications committed to"
						+ " local system master configuration file.");
					// Reinitialize the memory-resident SSLContext to apply changes instantly
					refreshSSLContext();
				} catch (IOException e) {
					System.err.println("Critical error - Failed to generate backup artifact. " 
							+ "Aborting cacerts update transaction to prevent data corruption.");
					logger.fatal("Disk IO checkpoint exception caught while writing state to physical environment container files. "
							+ "Transaction aborted.", e);
					throw e; // Terminate execution immediately to guard the primary keystore integrity
				}
			} else {
				System.out.println("All certificates in cacerts are up to date. No file rewriting is required.");
				logger.info("Operational integrity verified: Local runtime definitions are "
						+ "aligned with destination endpoints signatures.");
				
				// Initialize the execution profile context with the active keystore baseline
				refreshSSLContext();
			}
		} catch (Exception e) {
			System.err.println("Error during operational transactions with cacerts: " 
					+ e.getMessage());
			logger.error("Unhandled transactional execution scope runtime exception caught "
					+ "within the workspace tracker loop.", e);
			e.printStackTrace();
		}
	}
}