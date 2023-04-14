# SSLPoke

![Java CI with Maven](https://github.com/klasen/sslpoke/workflows/Java%20CI%20with%20Maven/badge.svg)

Test establishment of a TLS connection to a host with Java.

This version has been enhanced to print all known system and security properties relevant to TLS and HTTPS.

## Usage

Positive test:

```sh
java -jar sslpoke.jar www.github.com 443
```

You should get this:

```log
connecting to www.github.com:443 with the following system and security properties:
java.version: System: 1.8.0_251
java.vendor: System: Oracle Corporation
policy.allowSystemProperty: Security: true
java.security.policy:
CertPathValidator.PKIX:
cert.provider.x509v1:
java.protocol.handler.pkgs:
security.provider.1: Security: sun.security.provider.Sun
ssl.ServerSocketFactory.provider:
ssl.SocketFactory.provider:
jdk.tls.client.protocols:
jdk.tls.disabledAlgorithms: Security: SSLv3, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL
jdk.tls.legacyAlgorithms: Security: K_NULL, C_NULL, M_NULL, DH_anon, ECDH_anon, RC4_128, RC4_40, DES_CBC, DES40_CBC, 3DES_EDE_CBC
jdk.tls.ephemeralDHKeySize:
jsse.enableSNIExtension:
https.cipherSuites:
https.protocols:
sun.security.ssl.allowUnsafeRenegotiation:
sun.security.ssl.allowLegacyHelloMessages:
keystore.type: Security: jks
keystore.type.compat: Security: true
javax.net.ssl.trustStore:
javax.net.ssl.trustStorePassword:
javax.net.ssl.trustStoreType:
javax.net.ssl.keyStore:
javax.net.ssl.keyStorePassword:
javax.net.ssl.keyStoreType:
CertPathValidator.PKIX:
jdk.certpath.disabledAlgorithms: Security: MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224
com.sun.net.ssl.checkRevocation:
com.sun.security.enableCRLDP:
com.sun.security.crl.timeout:
sun.security.certpath.ldap.cache.lifetime:
com.sun.security.enableAIAcaIssuers:
ocsp.enable:
ocsp.responderURL:
ocsp.responderCertSubjectName:
ocsp.responderCertIssuerName:
ocsp.responderCertSerialNumber:
http.nonProxyHosts:
https.protocols:
https.proxyHost:
https.proxyPort:
java.security.debug:
javax.net.debug:

Successfully connected.
Protocol: TLSv1.2
Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

Negative tests (courtesy of [badssl.com](https://badssl.com)):

```
java -jar sslpoke.jar expired.badssl.com 443
java -jar sslpoke.jar wrong.host.badssl.com 443
java -jar sslpoke.jar self-signed.badssl.com 443
java -jar sslpoke.jar untrusted-root.badssl.com 443
java -jar sslpoke.jar revoked.badssl.com 443
java -jar sslpoke.jar cbc.badssl.com 443
java -jar sslpoke.jar rc4-md5.badssl.com 443
java -jar sslpoke.jar rc4.badssl.com 443
java -jar sslpoke.jar 3des.badssl.com 443
java -jar sslpoke.jar null.badssl.com 443
java -jar sslpoke.jar tls-v1-0.badssl.com 1010
java -jar sslpoke.jar tls-v1-1.badssl.com 1011
java -jar sslpoke.jar tls-v1-2.badssl.com 1012
```

Which should get you an error like this:

```log
[...]
Connection failed.
javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed
        at sun.security.ssl.Alerts.getSSLException(Unknown Source)
        at sun.security.ssl.SSLSocketImpl.fatal(Unknown Source)
        at sun.security.ssl.Handshaker.fatalSE(Unknown Source)
        at sun.security.ssl.Handshaker.fatalSE(Unknown Source)
        at sun.security.ssl.ClientHandshaker.serverCertificate(Unknown Source)
        at sun.security.ssl.ClientHandshaker.processMessage(Unknown Source)
        at sun.security.ssl.Handshaker.processLoop(Unknown Source)
        at sun.security.ssl.Handshaker.process_record(Unknown Source)
        at sun.security.ssl.SSLSocketImpl.readRecord(Unknown Source)
        at sun.security.ssl.SSLSocketImpl.performInitialHandshake(Unknown Source)
        at sun.security.ssl.SSLSocketImpl.writeRecord(Unknown Source)
        at sun.security.ssl.AppOutputStream.write(Unknown Source)
        at sun.security.ssl.AppOutputStream.write(Unknown Source)
        at SSLPoke.connect(SSLPoke.java:51)
        at SSLPoke.main(SSLPoke.java:84)
Caused by: sun.security.validator.ValidatorException: PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed
        at sun.security.validator.PKIXValidator.doValidate(Unknown Source)
        at sun.security.validator.PKIXValidator.engineValidate(Unknown Source)
        at sun.security.validator.Validator.validate(Unknown Source)
        at sun.security.ssl.X509TrustManagerImpl.validate(Unknown Source)
        at sun.security.ssl.X509TrustManagerImpl.checkTrusted(Unknown Source)
        at sun.security.ssl.X509TrustManagerImpl.checkServerTrusted(Unknown Source)
        ... 11 more
Caused by: java.security.cert.CertPathValidatorException: validity check failed
        at sun.security.provider.certpath.PKIXMasterCertPathValidator.validate(Unknown Source)
        at sun.security.provider.certpath.PKIXCertPathValidator.validate(Unknown Source)
        at sun.security.provider.certpath.PKIXCertPathValidator.validate(Unknown Source)
        at sun.security.provider.certpath.PKIXCertPathValidator.engineValidate(Unknown Source)
        at java.security.cert.CertPathValidator.validate(Unknown Source)
        ... 17 more
Caused by: java.security.cert.CertificateExpiredException: NotAfter: Mon Apr 13 01:59:59 CEST 2015
        at sun.security.x509.CertificateValidity.valid(Unknown Source)
        at sun.security.x509.X509CertImpl.checkValidity(Unknown Source)
        at sun.security.provider.certpath.BasicChecker.verifyValidity(Unknown Source)
        at sun.security.provider.certpath.BasicChecker.check(Unknown Source)
        ... 22 more
```

## Java Properties

The properties that influence the network, TLS protocol, certificate verification and debugging behavior of a JVM are described in:

- Java Secure Socket Extension (JSSE) Reference Guide ([Java 8](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#InstallationAndCustomization), [Java 11](https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-93DEEE16-0B70-40E5-BBE7-55C3FD432345))
- [Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html)
- [Networking Properties](https://docs.oracle.com/javase/8/docs/api/java/net/doc-files/net-properties.html)

So far, I've come across the following parameters that seem relevant:

- Policy
  - policy.allowSystemProperty
  - java.security.policy
- Implementation
  - cert.provider.x509v1
  - java.protocol.handler.pkgs
  - security.provider.1
  - ssl.ServerSocketFactory.provider
  - ssl.SocketFactory.provider
- Protocol
  - jdk.tls.client.protocols
  - jdk.tls.disabledAlgorithms
  - jdk.tls.legacyAlgorithms
  - jdk.tls.ephemeralDHKeySize
  - jsse.enableSNIExtension
  - https.cipherSuites
  - https.protocols
  - sun.security.ssl.allowUnsafeRenegotiation
  - sun.security.ssl.allowLegacyHelloMessages
- Stores
  - keystore.type (<https://docs.oracle.com/javase/8/docs/api/java/security/KeyStore.html>)
  - keystore.type.compat (<https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8192884>)
  - javax.net.ssl.trustStore
  - javax.net.ssl.trustStorePassword
  - javax.net.ssl.trustStoreType
  - javax.net.ssl.keyStore
  - javax.net.ssl.keyStorePassword
  - javax.net.ssl.keyStoreType
- Certificate path validation
  - CertPathValidator.PKIX
  - jdk.certpath.disabledAlgorithms
  - jdk.security.caDistrustPolicies
  - com.sun.net.ssl.checkRevocation
  - com.sun.security.enableCRLDP
  - com.sun.security.crl.timeout
  - sun.security.certpath.ldap.cache.lifetime
  - com.sun.security.enableAIAcaIssuers
  - ocsp.enable
  - ocsp.responderURL
  - ocsp.responderCertSubjectName
  - ocsp.responderCertIssuerName
  - ocsp.responderCertSerialNumber

- Proxy
  - http.nonProxyHosts
  - https.protocols
  - https.proxyHost
  - https.proxyPort

## Troubleshooting

To get increase the log level, set the following properties:

- java.security.debug
  - <https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#Debug>
  - <https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/ReadDebug.html>
  - suggested option: `-Djavax.net.debug=ssl`
- javax.net.debug
  - <https://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html>
  - suggested option: `-Djava.security.debug=certpath`

## Servers

To see the protocols and ciphers supported by the server you are trying to connect to you can use tools such as [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) if the server is publicly available or [sslscan](https://www.ssllabs.com/ssltest/) if you are in a private network.

## Credits

- Atlassian for the [base code](https://confluence.atlassian.com/display/JIRA052/Connecting+to+SSL+services)
- @4ndrej for <https://gist.github.com/4ndrej/4547029>
