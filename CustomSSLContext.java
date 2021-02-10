public class CustomSSLContext {

	private static final String KEY_ALIAS = "key";

	private static final char[] EMPTY_PASSWORD = {};

	private final File CA_CERT_FILE;

	private final File CERT_FILE;

	private final File KEY_FILE;

	private final KeyStore AUTH_KEY_STORE;

	private final KeyStore TRUST_KEY_STORE;

	private SSLContext sslContext;

	private Date clientCertRefreshDate;

	private Date caCertRefreshDate;

	private long refreshCertBeforeExpMillis;

	public CustomSSLContext(File caCertFile, File certFile, File keyFile)
			throws FileNotFoundException, CustomException {

		CA_CERT_FILE = caCertFile;
		if (!CA_CERT_FILE.exists()) {
			throw new FileNotFoundException(CA_CERT_FILE.toString());
		}

		CERT_FILE = certFile;
		if (!CERT_FILE.exists()) {
			throw new FileNotFoundException(CERT_FILE.toString());
		}

		KEY_FILE = keyFile;
		if (!KEY_FILE.exists()) {
			throw new FileNotFoundException(KEY_FILE.toString());
		}

		try {
			AUTH_KEY_STORE = createNewKeyStore();
			TRUST_KEY_STORE = createNewKeyStore();

		} catch (Exception e) {
			throw new FileNotFoundException(e.getMessage());
		}

		refreshSslContext();
	}

	public KeyManager[] getKeyMgrs() throws Exception {
		PrivateKey clientKey = readKeyFromFile(KEY_FILE);
		X509Certificate[] clientCerts = readCertsFromFile(CERT_FILE);
		addOrUpdateClientKey(clientKey, clientCerts, AUTH_KEY_STORE, KEY_ALIAS);

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(AUTH_KEY_STORE, EMPTY_PASSWORD);

		return kmf.getKeyManagers();
	}

	public TrustManager[] getTrustMgrs() throws Exception {
		X509Certificate[] caCerts = readCertsFromFile(CA_CERT_FILE);
		addOrUpdateTrustCerts(caCerts, TRUST_KEY_STORE);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(TRUST_KEY_STORE);
		return tmf.getTrustManagers();
	}

	public static RSAPrivateKey readKeyFromFile(File keyFile) throws Exception {
		BouncyIntegration.init();
		return (RSAPrivateKey) PrivateKeyFileReader.readFromFile(keyFile.getAbsolutePath(), null);
	}

	public static X509Certificate[] readCertsFromFile(File certFile) throws Exception {
		return CertificateFileReader.readFromFile(certFile.getPath());
	}

	protected void addOrUpdateClientKey(PrivateKey privateKey, X509Certificate[] certs, KeyStore keyStore,
			String keyAlias) {
		try {
			if (keyStore.containsAlias(keyAlias)) {
				keyStore.deleteEntry(keyAlias);
			}
			keyStore.setKeyEntry(keyAlias, privateKey, EMPTY_PASSWORD, certs);

			Date earliestExpDate = null;
			for (int i = 0; i < certs.length; i++) {
				earliestExpDate = getEarliestExpDate(earliestExpDate, certs[i]);
			}
			clientCertRefreshDate = getCertRefreshDate(earliestExpDate);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private Date getCertRefreshDate(Date notAfter) {
		return new Date(notAfter.getTime() - refreshCertBeforeExpMillis);
	}

	private Date getEarliestExpDate(Date earlierExpDate, X509Certificate cert) {
		if (earlierExpDate == null || cert.getNotAfter().before(earlierExpDate)) {
			earlierExpDate = cert.getNotAfter();
		}
		return earlierExpDate;
	}

	public static KeyStore createNewKeyStore()
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, EMPTY_PASSWORD);
		return keyStore;
	}

	private void addOrUpdateTrustCerts(X509Certificate[] certs, KeyStore trustStore) {
		try {
			if (trustStore.size() > 0) {
				List<String> aliasesToDelete = Lists.newArrayList();
				Enumeration<String> aliases = TRUST_KEY_STORE.aliases();

				while (aliases.hasMoreElements()) {
					aliasesToDelete.add(aliases.nextElement());
				}

				for (String alias : aliasesToDelete) {
					TRUST_KEY_STORE.deleteEntry(alias);
				}
			}

			Date earliestExpDate = null;
			for (int i = 0; i < certs.length; i++) {
				TRUST_KEY_STORE.setCertificateEntry("cert-" + i, certs[i]);
				earliestExpDate = getEarliestExpDate(earliestExpDate, certs[i]);
			}

			caCertRefreshDate = getCertRefreshDate(earliestExpDate);

		} catch (KeyStoreException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public void refreshSslContext() throws CustomException {
		try {
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(getKeyMgrs(), getTrustMgrs(), new SecureRandom());
			this.sslContext = sslContext;

		} catch (Exception e) {
			throw new CustomException(e.getMessage(), e);
		}

		if (shouldRefreshContext()) {
			throw new CustomException("ssl");
		}
	}

	public boolean shouldRefreshContext() {
		Date now = new Date();
		return sslContext == null || clientCertRefreshDate == null || now.after(clientCertRefreshDate)
				|| now.after(caCertRefreshDate);
	}

	public SSLContext getSslContext() {
		return sslContext;
	}
}
