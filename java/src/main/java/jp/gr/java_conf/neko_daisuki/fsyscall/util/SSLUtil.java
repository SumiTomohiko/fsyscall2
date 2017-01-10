package jp.gr.java_conf.neko_daisuki.fsyscall.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class SSLUtil {

    public static SSLContext createContext(InputStream trustKeyStore,
                                           String trustKeyStorePassword)
                                           throws CertificateException,
                                                  IOException,
                                                  KeyManagementException,
                                                  KeyStoreException,
                                                  NoSuchAlgorithmException {
        SSLContext context = SSLContext.getInstance("TLS");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] password = trustKeyStorePassword.toCharArray();
        keyStore.load(trustKeyStore, password);

        String algo = "SunX509";
        TrustManagerFactory factory = TrustManagerFactory.getInstance(algo);
        factory.init(keyStore);
        TrustManager[] tm = factory.getTrustManagers();

        context.init(null, tm, null);

        return context;
    }

    public static SSLContext createContext(String trustKeyStorePath,
                                           String trustKeyStorePassword)
                                           throws CertificateException,
                                                  IOException,
                                                  KeyManagementException,
                                                  KeyStoreException,
                                                  NoSuchAlgorithmException {
        return createContext(new FileInputStream(trustKeyStorePath),
                             trustKeyStorePassword);
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
