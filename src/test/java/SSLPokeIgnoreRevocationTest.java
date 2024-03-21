import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.ClearSystemProperty;

/**
 * Unit test.
 */
@ClearSystemProperty(key = "com.sun.net.ssl.checkRevocation")
@ClearSystemProperty(key = "com.sun.security.enableCRLDP")
public class SSLPokeIgnoreRevocationTest {

    @Test
    public void ignoreRevocation() throws UnknownHostException, IOException {
        assertNotNull(SSLPoke.connect("revoked-rsa-dv.ssl.com", 443));
    }

}
