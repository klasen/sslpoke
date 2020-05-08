import org.junit.Test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.UnknownHostException;

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

    @Test(expected=javax.net.ssl.SSLHandshakeException.class)
    public void selfSignedBadSslCom() throws UnknownHostException, IOException {
        SSLPoke.connect("self-signed.badssl.com", 443);
    }

    @Test(expected=java.net.UnknownHostException.class)
    public void hostUnknown() throws UnknownHostException, IOException {
        SSLPoke.connect("host.unknown", 443);
    }
}
