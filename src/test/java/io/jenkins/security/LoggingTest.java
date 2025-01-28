package io.jenkins.security;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.instrument.IllegalClassFormatException;

public class LoggingTest {

    @Test
    void logMessagePrefixedWhenSkippingTransformation() {
        // Ensure the log message is prefixed with "SECURITY-3430 Workaround: " when skipping transformation
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        System.setProperty(Security3430Workaround.class.getName() + ".DISABLE", "true");
        Security3430Workaround transformer = new Security3430Workaround();
        try {
            transformer.transform(null, "hudson/remoting/RemoteClassLoader$ClassLoaderProxy", null, null, new byte[0]);
        } catch (IllegalClassFormatException e) {
            //ignore
        }
        assertTrue(outContent.toString().startsWith("SECURITY-3430 Workaround: Skipping transformation of"));
        System.clearProperty(Security3430Workaround.class.getName() + ".DISABLE");
        System.setOut(System.out);
    }
}