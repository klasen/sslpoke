import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;

/**
 * Unit test.
 */
public class SSLPokeTest {
    /**
     * Rigorous Test.
     * 
     * @throws IOException
     * @throws UnknownHostException
     */
    @Test
    public void wwwGithubCom() throws UnknownHostException, IOException {
        Object result = SSLPoke.connect("www.github.com", 443);
        assertNotNull(result);
    }

    @Test
    public void unknownHost() throws UnknownHostException, IOException {

        assertThrows(java.net.UnknownHostException.class,
                () -> SSLPoke.connect("host.invalid", 443));
    }

    @Test
    public void expired() throws UnknownHostException, IOException {
        assertThrows(javax.net.ssl.SSLHandshakeException.class,
                () -> SSLPoke.connect("expired.badssl.com", 443));

    }

    // @Test
    // public void wrongHost() throws UnknownHostException, IOException {
    //     assertThrows(javax.net.ssl.SSLHandshakeException.class,
    //             () -> SSLPoke.connect("wrong.host.badssl.com", 443));
    // }

    @Test
    public void selfSigned() throws UnknownHostException, IOException {
        assertThrows(javax.net.ssl.SSLHandshakeException.class,
                () -> SSLPoke.connect("self-signed.badssl.com", 443));
    }

    @Test
    public void untrustedRoot() throws UnknownHostException, IOException {
        assertThrows(javax.net.ssl.SSLHandshakeException.class,
                () -> SSLPoke.connect("untrusted-root.badssl.com", 443));
    }

    @Test
    @SetSystemProperty(key = "jdk.tls.client.protocols", value = "SSLv3")
    public void sslV3() throws UnknownHostException, IOException {
        assertThrows(javax.net.ssl.SSLHandshakeException.class,
                () -> SSLPoke.connect("www.badssl.com", 443));
    }

    // https://github.com/chromium/badssl.com/issues/515
    // @Test
    // @SetSystemProperty(key = "com.sun.net.ssl.checkRevocation", value = "false")
    // @SetSystemProperty(key = "com.sun.security.enableCRLDP", value = "true")
    // public void ignoreRevocation() throws UnknownHostException, IOException {
    //     assertNotNull(SSLPoke.connect("revoked.badssl.com", 443));
    // }

    // @Test
    // @SetSystemProperty(key = "com.sun.net.ssl.checkRevocation", value = "true")
    // @SetSystemProperty(key = "com.sun.security.enableCRLDP", value = "true")
    // public void revoked() throws UnknownHostException, IOException {
    //     assertEquals("true", System.getProperty("com.sun.net.ssl.checkRevocation"));
    //     Exception exception = assertThrows(javax.net.ssl.SSLHandshakeException.class,
    //             () -> SSLPoke.connect("revoked.badssl.com", 443));
    //     assertTrue(exception.getMessage().contains("Certificate has been revoked"));
    // }
}
