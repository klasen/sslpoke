import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Test establishment of a HTTPS (TLS) connection to a host and port
 * 
 * @see https://gist.github.com/4ndrej/4547029
 */
public class SSLPoke {
    // https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-A41282C3-19A3-400A-A40F-86F4DA22ABA9
    final static String[] securityPropertyNames = {
            "cert.provider.x509v1",
            "com.sun.CORBA.ORBIorTypeCheckRegistryFilter",
            "crypto.policy",
            "fips.keystore.type",
            "fips.provider.1",
            "fips.provider.2",
            "fips.provider.3",
            "fips.provider.4",
            "jceks.key.serialFilter",
            "jdk.certpath.disabledAlgorithms",
            "jdk.disabled.namedCurves",
            "jdk.includeInExceptions",
            "jdk.io.permissionsUseCanonicalPath",
            "jdk.jar.disabledAlgorithms",
            "jdk.jceks.iterationCount",
            "jdk.jndi.object.factoriesFilter",
            "jdk.sasl.disabledMechanisms",
            "jdk.security.allowNonCaAnchor",
            "jdk.security.caDistrustPolicies",
            "jdk.security.krb5.default.initiate.credential",
            "jdk.security.legacyAlgorithms",
            "jdk.security.provider.preferred",
            "jdk.serialFilter",
            "jdk.tls.alpnCharset",
            "jdk.tls.disabledAlgorithms",
            "jdk.tls.keyLimits",
            "jdk.tls.legacyAlgorithms",
            "jdk.tls.server.defaultDHEParameters",
            "jdk.xml.dsig.secureValidationPolicy",
            "keystore.pkcs12.certPbeIterationCount",
            "keystore.pkcs12.certProtectionAlgorithm",
            "keystore.pkcs12.keyPbeIterationCount",
            "keystore.pkcs12.keyProtectionAlgorithm",
            "keystore.pkcs12.macAlgorithm",
            "keystore.pkcs12.macIterationCount",
            "keystore.type",
            "keystore.type.compat",
            "krb5.kdc.bad.policy",
            "login.config.url.1",
            "login.configuration.provider",
            "networkaddress.cache.negative.ttl",
            "networkaddress.cache.ttl",
            "ocsp.enable",
            "package.access",
            "package.definition",
            "policy.allowSystemProperty",
            "policy.expandProperties",
            "policy.ignoreIdentityScope",
            "policy.provider",
            "policy.url.1",
            "policy.url.2",
            "securerandom.drbg.config",
            "securerandom.source",
            "securerandom.strongAlgorithms",
            "security.overridePropertiesFile",
            "security.provider.1",
            "security.provider.10",
            "security.provider.11",
            "security.provider.12",
            "security.provider.2",
            "security.provider.3",
            "security.provider.4",
            "security.provider.5",
            "security.provider.6",
            "security.provider.7",
            "security.provider.8",
            "security.provider.9",
            "security.useSystemPropertiesFile",
            "ssl.KeyManagerFactory.algorithm",
            "ssl.ServerSocketFactory.provider",
            "ssl.SocketFactory.provider",
            "ssl.TrustManagerFactory.algorithm",
            "sun.rmi.registry.registryFilter",
            "sun.rmi.transport.dgcFilter",
            "sun.security.krb5.disableReferrals",
            "sun.security.krb5.maxReferrals",
    };

    final static String[] systemPropertyNames = {
            "java.vendor",
            "java.version",
            "java.security.debug",
            "javax.net.debug",
            // https://docs.oracle.com/en/java/javase/11/security/permissions-jdk1.html#GUID-BFF84712-05CF-4C1E-926F-411FDF83AE32
            "java.security.policy",
            // system proxy
            "http_proxy",
            "https_proxy",
            "no_proxy",
            // https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-A41282C3-19A3-400A-A40F-86F4DA22ABA9
            "com.sun.net.ssl.checkRevocation",
            "https.cipherSuites",
            "https.protocols",
            "https.proxyHost",
            "https.proxyPort",
            "http.nonProxyHosts", // https://docs.oracle.com/javase/8/docs/api/java/net/doc-files/net-properties.html
            "java.protocol.handler.pkgs",
            "javax.net.ssl.keyStore",
            "javax.net.ssl.keyStorePassword",
            "javax.net.ssl.keyStoreProvider",
            "javax.net.ssl.keyStoreType",
            "javax.net.ssl.sessionCacheSize",
            "javax.net.ssl.trustStore",
            "javax.net.ssl.trustStorePassword",
            "javax.net.ssl.trustStoreProvider",
            "javax.net.ssl.trustStoreType",
            "jdk.tls.acknowledgeCloseNotify",
            "jdk.tls.allowUnsafeServerCertChange",
            "jdk.tls.client.cipherSuites",
            "jdk.tls.client.disableExtensions",
            "jdk.tls.client.protocols",
            "jdk.tls.client.SignatureSchemes",
            "jdk.tls.ephemeralDHKeySize",
            "jdk.tls.maxCertificateChainLength",
            "jdk.tls.maxHandshakeMessageSize",
            "jdk.tls.namedGroups",
            "jdk.tls.server.cipherSuites",
            "jdk.tls.server.disableExtensions",
            "jdk.tls.server.protocols",
            "jdk.tls.server.SignatureSchemes",
            "jsse.enableFFDHE",
            "jsse.enableMFLNExtension",
            "jsse.enableSNIExtension",
            "jsse.SSLEngine.acceptLargeFragments",
            "sun.security.ssl.allowLegacyHelloMessages",
            "sun.security.ssl.allowUnsafeRenegotiation",
            // https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-FF62B0E3-E57A-4F40-970A-0481AF750CCD
            "sun.security.certpath.ldap.cache.lifetime",
            // https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-EB250086-0AC1-4D60-AE2A-FC7461374746
            "com.sun.security.crl.timeout",
            "com.sun.security.enableAIAcaIssuers",
            "com.sun.security.enableCRLDP",
    };

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

        System.out.println("connecting to " + host + ":" + port);

        System.out.println("System properties:");
        for (int i = 0; i < systemPropertyNames.length; i++) {
            final String value = System.getProperty(systemPropertyNames[i]);
            if (value != null) {
                System.out.println(systemPropertyNames[i] + ": " + value);
            }
        }

        // dump all system properties
        // Properties systemProperties = System.getProperties();
        // for (Entry<Object, Object> property : systemProperties.entrySet()) {
        // System.out.println(property.getKey() + ":" + property.getValue());
        // }

        System.out.println();

        System.out.println("security properties:");
        for (int i = 0; i < securityPropertyNames.length; i++) {
            final String value = java.security.Security.getProperty(securityPropertyNames[i]);
            if (value != null) {
                System.out.println(securityPropertyNames[i] + ": " + value);
            }
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
