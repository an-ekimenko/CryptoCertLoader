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
import java.security.KeyStore;
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

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;


public class KeyStoreManager {
	private static final String PASSWORD = "changeit";
	
	// ==========================================
    // SSLCONTEXT MANAGEMENT IN MEMORY
    // ==========================================
    private static SSLContext currentSslContext;

    static {
        // Primary initialization by the standard JVM context at the start of the application.
        try {
            currentSslContext = SSLContext.getDefault();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize default SSLContext", e);
        }
    }

    /**
     * A getter for obtaining the current SSLContext (called from Apache HttpClient).
     */
    public static SSLContext getSSLContext() {
        return currentSslContext;
    }

    /**
     * Reads the cacerts file from the disk and updates the SSLContext in memory on the fly.
     */
    public static void refreshSSLContext() {
        try {
            File cacertsFile = getCacertsFile();
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            
            try (InputStream is = new FileInputStream(cacertsFile)) {
                keyStore.load(is, PASSWORD.toCharArray());
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());

            currentSslContext = sslContext;
            System.out.println("SSLContext in memory has been successfully refreshed with updated certificates.");
        } catch (Exception e) {
            System.err.println("Failed to refresh SSLContext in memory: " + e.getMessage());
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
                        // Grabbing the chain of certificates straight from the network.
                        serverCertificatesRef.set(certs);
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());

            // Disable hostname validation in case the server’s domain/IP address does not match.          
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");

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
                    //String authString = username + ":" + password;
                    //String encodedAuth = Base64.getEncoder().encodeToString(authString.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    String encodedAuth = Base64.getEncoder().encodeToString(credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    requestBuilder.header("Authorization", "Basic " + encodedAuth);
                    System.out.println("SSL Interception - the Basic Auth header is applied.");
                    
                } else if (("TOKEN".equals(upperAuthType) || "BEARER".equals(upperAuthType)) && credentials != null) {
                	// If the type is TOKEN, then the token itself is passed in the credentials parameter.
                    requestBuilder.header("Authorization", "Bearer " + credentials);
                    System.out.println("SSL Interception - the Token Auth header is applied.");
                }
            }
            
            HttpRequest request = requestBuilder.build();

            /**
             * Send the request. It doesn’t matter what the server returns — at the moment of connection, 
             * checkServerTrusted will run and place the certificates in interceptedCerts.
             */
            client.send(request, 
            		/**
            		 * HttpResponse.BodyHandlers.discarding() immediately destroys the incoming JSON text,
                     * without wasting memory on it.
            		 */
            		HttpResponse.BodyHandlers.discarding()); 

            X509Certificate[] interceptedCerts = serverCertificatesRef.get();
            
            if (interceptedCerts != null && interceptedCerts.length > 0) {
                // Return the chain intercepted from the network as a collection.
                return Arrays.asList(interceptedCerts);
            } else {
                throw new IOException("Failed to intercept SSL certificates during the connection.");
            }

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
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
        try {
            // 1 - Download the current certificate chain from the server, taking into account the authorization type.
            Collection<? extends java.security.cert.Certificate> remoteCerts = 
            									downloadRemoteCertificates(downloadUrl, credentials, authType);
            System.out.println("The chain has been successfully intercepted; \n"
            		       		+ remoteCerts.size() + " certificates have been found.");

            // 2 - Loading the current system storage cacerts.
            File cacertsFile = getCacertsFile();
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream is = new FileInputStream(cacertsFile)) {
                keyStore.load(is, PASSWORD.toCharArray());
            }
            
            System.out.println("The current system storage cacerts were loaded.");
            
            boolean isUpdatedNeeded = false;
            Date now = new Date();

            // 3 - Check each downloaded certificate within our cacerts.
            for (java.security.cert.Certificate cert : remoteCerts) {
                if (cert instanceof X509Certificate) {
                    X509Certificate remoteCert = (X509Certificate) cert;
                    
                    /* X500Principal - the "passport data" of the certificate owner or the entity that issued the certificate.
                     * Subject - to whom the certificate was issued; Issuer - who issued and signed this certificate.  
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
                            } catch (CertificateException e) {
                                // The local certificate is outdated - we’re overwriting it with a new one.
                                System.out.println("The certificate " + subject.getName() +
                                		" in cacerts is outdated -> we are updating it.");
                                keyStore.setCertificateEntry(alias, remoteCert);
                                isUpdatedNeeded = true;
                            }
                        }
                    } else {
                        // If such a certificate is not in the repository at all, we add it.
                        System.out.println("The new certificate "  + subject.getName()
                        				   + "has been detected -> adding it to cacerts.");
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
                    
                    // Commit the modified KeyStore state to the primary systemic cacerts file
                    try (FileOutputStream fos = new FileOutputStream(cacertsFile)) {
                        keyStore.store(fos, PASSWORD.toCharArray());
                    }
                    System.out.println("The cacerts file has been successfully updated on the disk.");
                    
                    // Reinitialize the memory-resident SSLContext to apply changes instantly
                    refreshSSLContext();
                    
                } catch (IOException e) {
                    System.err.println("Critical error - Failed to generate backup artifact. " +
                                       "Aborting cacerts update transaction to prevent data corruption.");
                    throw e; // Terminate execution immediately to guard the primary keystore integrity
                }
            } else {
                System.out.println("All certificates in cacerts are up to date. No file rewriting is required.");
                
                // Initialize the execution profile context with the active keystore baseline
                refreshSSLContext();
            }

        } catch (Exception e) {
            System.err.println("Error during operational transactions with cacerts: " + e.getMessage());
            e.printStackTrace();
        }
    }

}

