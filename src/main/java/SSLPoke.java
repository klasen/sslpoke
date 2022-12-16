import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;

import java.io.*;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Test establishment of a HTTPS (TLS) connection to a host and port
 * 
 * @see https://gist.github.com/4ndrej/4547029
 */
public class SSLPoke {
    final static String[] propertyNames = {
            // Info
            "java.version", "java.vendor",
            // Policy
            "policy.allowSystemProperty", "java.security.policy", "CertPathValidator.PKIX", "cert.provider.x509v1",
            "java.protocol.handler.pkgs", "security.provider.1", "ssl.ServerSocketFactory.provider",
            "ssl.SocketFactory.provider",
            // Protocol
            "jdk.tls.client.protocols", "jdk.tls.disabledAlgorithms", "jdk.tls.legacyAlgorithms",
            "jdk.tls.ephemeralDHKeySize", "jsse.enableSNIExtension", "https.cipherSuites", "https.protocols",
            "sun.security.ssl.allowUnsafeRenegotiation", "sun.security.ssl.allowLegacyHelloMessages",
            // Stores
            "keystore.type", "keystore.type.compat", "javax.net.ssl.trustStore", "javax.net.ssl.trustStorePassword",
            "javax.net.ssl.trustStoreType", "javax.net.ssl.keyStore", "javax.net.ssl.keyStorePassword",
            "javax.net.ssl.keyStoreType",
            // Validation
            "CertPathValidator.PKIX", "jdk.certpath.disabledAlgorithms", "jdk.security.caDistrustPolicies",
            "com.sun.net.ssl.checkRevocation", "com.sun.security.enableCRLDP", "com.sun.security.crl.timeout",
            "sun.security.certpath.ldap.cache.lifetime", "com.sun.security.enableAIAcaIssuers", "ocsp.enable",
            "ocsp.responderURL", "ocsp.responderCertSubjectName", "ocsp.responderCertIssuerName",
            "ocsp.responderCertSerialNumber",
            // Proxy
            "http.nonProxyHosts", "https.protocols", "https.proxyHost", "https.proxyPort",
            // Debug
            "java.security.debug", "javax.net.debug" };

    static SSLSession connect(final String host, final int port) throws UnknownHostException, IOException {
        SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(host, port);

        SSLParameters sslparams = new SSLParameters();
        sslsocket.setSSLParameters(sslparams);

        sslparams.setEndpointIdentificationAlgorithm("HTTPS");

        // Sets Server Name Indication (SNI) parameter.
        final SNIHostName serverName = new SNIHostName(host);
        final List<SNIServerName> serverNames = new ArrayList<>(1);
        serverNames.add(serverName);
        sslparams.setServerNames(serverNames);

        InputStream in = sslsocket.getInputStream();
        OutputStream out = sslsocket.getOutputStream();

        // Write a test byte to get a reaction :)
        out.write(1);

        while (in.available() > 0) {
            System.out.print(in.read());
        }

        return sslsocket.getSession();
    }

    public static void main(final String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: " + SSLPoke.class.getName() + " <host> <port>");
            System.exit(1);
        }
        final String host = args[0];
        final Integer port = Integer.parseInt(args[1]);

        // System.setProperty("java.security.debug", "certpath");
        // System.setProperty("javax.net.debug", "ssl");
        // System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        // System.setProperty("com.sun.security.enableCRLDP", "true");

        System.out
                .println("connecting to " + host + ":" + port + " with the following system and security properties:");
        for (int i = 0; i < propertyNames.length; i++) {
            final String systemProperty = System.getProperty(propertyNames[i]);
            final String securityProperty = java.security.Security.getProperty(propertyNames[i]);
            System.out.println(propertyNames[i] + ":" + (systemProperty != null ? " System: " + systemProperty : "")
                    + (securityProperty != null ? " Security: " + securityProperty : ""));
        }
        System.out.println();

        try {
            SSLSession sslSession = connect(host, port);
            System.out.println("Successfully connected.");
            System.out.println("Protocol: " + sslSession.getProtocol());
            System.out.println("Cipher suite: " + sslSession.getCipherSuite());
        } catch (final Exception exception) {
            System.out.println("Connection failed.");
            exception.printStackTrace();
            System.exit(1);
        }
    }
}
