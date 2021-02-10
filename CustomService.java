public class CustomService {

  public SSLContext getSSLContext() throws CustomException {
      SSLContext sslContext = null;
      try {
        if (isValidString(certDir) == false) {
          throw new CustomException();
        }
        String caCertFilePath = certDir + "/ca/cacerts.pem";
        String certFilePath = certDir + "/peer/certificates/peer.pem";
        String KeyFilePath = certDir + "/peer/keys/peer-key.pem";
        File caCertFile = Paths.get(caCertFilePath).toFile();
        File certFile = Paths.get(certFilePath).toFile();
        File keyFile = Paths.get(KeyFilePath).toFile();
        CustomSSLContext sslSecurityContext = new CustomSSLContext(caCertFile, certFile,
            keyFile);
        sslContext = sslSecurityContext.getSslContext();
        if (sslContext == null) {
          throw new CustomException();
        }
      } catch (Exception ex) {
        throw new CustomException();
      }
      return sslContext;
   }
 }
