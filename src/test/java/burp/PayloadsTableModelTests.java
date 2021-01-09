package burp;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.junit.jupiter.api.Test;
import rpm.Payload;
import rpm.model.PayloadsTableModel;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;

public class PayloadsTableModelTests {

    @Test
    void payloadTableModel_payloadContentForwardSlashStarCannotBeSetToTrueForIsRegex(){
        List<Payload> payloads = new ArrayList<Payload>();
        payloads.add(new Payload("admin", false, true));
        payloads.add(new Payload("password", false, true));
        payloads.add(new Payload("passcode", false, true));
        payloads.add(new Payload("port.{0,7}\\d+", true, true));
        payloads.add(new Payload("sql", false, true));
        payloads.add(new Payload("<!--", false, true));
        payloads.add(new Payload("/*", false, true));
        payloads.add(new Payload("todo", false, true));
        payloads.add(new Payload("secret", false, true));
        payloads.add(new Payload("//# sourceURL", false, true));
        payloads.add(new Payload("//# sourceMappingURL", false, true));
        payloads.add(new Payload("api", false, true));
        payloads.add(new Payload("private", false, true));
        payloads.add(new Payload("debug", false, true));
        payloads.add(new Payload("/*", false, true));

        PayloadsTableModel payloadsTableModel = new PayloadsTableModel(payloads, null);

        //Column 2 (Active) can always be editable
        assertTrue(payloadsTableModel.isCellEditable(3,2));

        //Column 2 (Active) can always be editable
        assertTrue(payloadsTableModel.isCellEditable(6,2));

        //Column 1 (is regex) can be editable as long as it's not /*
        assertTrue(payloadsTableModel.isCellEditable(1, 1));

        //Column 1 (is regex) cannot be editable if its /*
        assertFalse(payloadsTableModel.isCellEditable(6, 1));

        //Column 1 (is regex) cannot be editable if its /*
        assertFalse(payloadsTableModel.isCellEditable(14, 1));
    }

    @Test
    void payloadTableModel_getValueAtMethodReturnsCorrectItem(){
        List<Payload> payloads = new ArrayList<Payload>();
        payloads.add(new Payload("admin", false, true));
        payloads.add(new Payload("password", false, true));
        payloads.add(new Payload("passcode", false, true));
        payloads.add(new Payload("port.{0,7}\\d+", true, true));
        payloads.add(new Payload("sql", false, true));
        payloads.add(new Payload("<!--", false, true));
        payloads.add(new Payload("/*", false, true));
        payloads.add(new Payload("todo", false, true));
        payloads.add(new Payload("secret", false, true));
        payloads.add(new Payload("//# sourceURL", false, true));
        payloads.add(new Payload("//# sourceMappingURL", false, true));
        payloads.add(new Payload("api", false, true));
        payloads.add(new Payload("private", false, false));
        payloads.add(new Payload("debug", false, true));
        payloads.add(new Payload("/*", false, true));

        PayloadsTableModel payloadsTableModel = new PayloadsTableModel(payloads, null);

        assertEquals("passcode", payloadsTableModel.getValueAt(2,0));
        assertEquals("sql", payloadsTableModel.getValueAt(4,0));
        assertEquals("private", payloadsTableModel.getValueAt(12,0));

        assertEquals(false, payloadsTableModel.getValueAt(2,1));
        assertEquals(false, payloadsTableModel.getValueAt(14,1));
        assertEquals(true, payloadsTableModel.getValueAt(3,1));

        assertEquals(true, payloadsTableModel.getValueAt(2,2));
        assertEquals(true, payloadsTableModel.getValueAt(14,2));
        assertEquals(false, payloadsTableModel.getValueAt(12,2));
    }

    @Test
    void payloadTableModel_setValueAtUpdatesPayloadsCorrectly(){
        List<Payload> payloads = new ArrayList<Payload>();
        payloads.add(new Payload("admin", false, true));
        payloads.add(new Payload("password", false, true));
        payloads.add(new Payload("passcode", false, true));
        payloads.add(new Payload("port.{0,7}\\d+", true, true));
        payloads.add(new Payload("sql", false, true));
        payloads.add(new Payload("<!--", false, true));
        payloads.add(new Payload("/*", false, true));
        payloads.add(new Payload("todo", false, true));
        payloads.add(new Payload("secret", false, true));
        payloads.add(new Payload("//# sourceURL", false, true));
        payloads.add(new Payload("//# sourceMappingURL", false, true));
        payloads.add(new Payload("api", false, true));
        payloads.add(new Payload("private", false, false));
        payloads.add(new Payload("debug", false, true));
        payloads.add(new Payload("/*", false, true));

        Preferences prefs = mock(Preferences.class);

        PayloadsTableModel payloadsTableModel = new PayloadsTableModel(payloads, prefs);

        payloadsTableModel.setValueAt("shouldNotUpdate", 0, 0);
        payloadsTableModel.setValueAt(true, 2, 1);
        payloadsTableModel.setValueAt(false, 3, 2);

        assertEquals(payloads.get(0).getContent(), "admin");
        assertTrue(payloads.get(2).getIsRegex());
        assertFalse(payloads.get(3).getActive());
    }
}
