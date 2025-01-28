package io.jenkins.security;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.instrument.IllegalClassFormatException;
import org.junit.jupiter.api.Test;

public class LoggingTest {

    @Test
    void logMessagePrefixedWhenSkippingTransformation() {
        // Ensure the log message is prefixed with "INFO SECURITY-3430 Workaround: " when skipping transformation
        PrintStream originalOut = System.out;
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        System.setProperty(Security3430Workaround.class.getName() + ".DISABLE", "true");
        Security3430Workaround transformer = new Security3430Workaround();
        try {
            transformer.transform(null, "hudson/remoting/RemoteClassLoader$ClassLoaderProxy", null, null, new byte[0]);
        } catch (IllegalClassFormatException e) {
            // ignore
        } finally {
            assertTrue(outContent.toString().contains("INFO SECURITY-3430 Workaround: Skipping transformation of"));
            System.clearProperty(Security3430Workaround.class.getName() + ".DISABLE");
            System.setOut(originalOut);
        }
    }
}
