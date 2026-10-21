package my;

public class CertUpdater {
	/**
     * Method that can be called from any application using Basic Auth.
     */
    public static void updateByBasicAuth(String url, String username, String password) {
        KeyStoreManager.checkAndDownloadCertificateChain(url, username + ":" + password, "BASIC");
    }

    /**
     * Method for calling by Token.
     */
    public static void updateByToken(String url, String token) {
        KeyStoreManager.checkAndDownloadCertificateChain(url, token, "TOKEN");
    }

    /**
     * Call for public URLs without authorization.
     */
    public static void updateWithoutAuth(String url) {
        KeyStoreManager.checkAndDownloadCertificateChain(url, null, null);
    }
}
