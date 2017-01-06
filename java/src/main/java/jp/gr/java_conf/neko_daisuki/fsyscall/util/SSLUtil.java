package jp.gr.java_conf.neko_daisuki.fsyscall.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class SSLUtil {

    public static SSLContext createContext(String trustKeyStorePath,
                                           String trustKeyStorePassword)
                                           throws CertificateException,
                                                  IOException,
                                                  KeyManagementException,
                                                  KeyStoreException,
                                                  NoSuchAlgorithmException {
        SSLContext context = SSLContext.getInstance("TLS");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] password = trustKeyStorePassword.toCharArray();
        keyStore.load(new FileInputStream(trustKeyStorePath), password);

        String algo = "SunX509";
        TrustManagerFactory factory = TrustManagerFactory.getInstance(algo);
        factory.init(keyStore);
        TrustManager[] tm = factory.getTrustManagers();

        context.init(null, tm, null);

        return context;
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab softtabstop=4
