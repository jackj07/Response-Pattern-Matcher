package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BurpExtenderTest {

    @Test
    void getToolFlag() {
        BurpExtender extender = new BurpExtender();
        assertEquals(extender.getToolFlag(), 0);
    }
}