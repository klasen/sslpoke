import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.ClearSystemProperty;
import org.junitpioneer.jupiter.SetSystemProperty;

/**
 * Unit test.
 */
@ClearSystemProperty(key = "com.sun.net.ssl.checkRevocation")
@ClearSystemProperty(key = "com.sun.security.enableCRLDP")
public class SSLPokeClientProtocolTest {

    @Test
    @SetSystemProperty(key = "jdk.tls.client.protocols", value = "SSLv3")
    public void sslV3() throws UnknownHostException, IOException {
        assertThrows(javax.net.ssl.SSLHandshakeException.class,
                () -> SSLPoke.connect("www.badssl.com", 443));
    }
}
