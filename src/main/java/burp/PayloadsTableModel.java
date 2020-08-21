package burp;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class PayloadsTableModel extends AbstractTableModel {

    List<Payload> payloads;
    Preferences prefs;
    PayloadsTableModel(List<Payload> payloads, Preferences prefs){
        this.payloads = payloads;
        this.prefs = prefs;
    }

    @Override
    public int getRowCount() {
        return payloads.size();
    }

    @Override
    public int getColumnCount() { return 3; }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Payload";
            case 1:
                return "Is Regex";
            case 2:
                return "Active";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        switch(columnIndex){
            case 0:
                return String.class;
            case 1:
                return Boolean.class;
            case 2:
                return Boolean.class;
            default:
                return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        if (col == 1) {
            if(payloads.get(row).content.equals("/*")) return false;
            return true;
        } else if(col == 2) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch(columnIndex) {
            case 0:
                return payloads.get(rowIndex).content;
            case 1:
                return payloads.get(rowIndex).isRegex;
            case 2:
                return payloads.get(rowIndex).active;
            default:
                return payloads.get(rowIndex).content;
        }
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        super.setValueAt(value, row, col);

        if (col == 1) {
            if ((Boolean) this.getValueAt(row, col) == true) {
                payloads.set(row, new Payload(payloads.get(row).content,false, payloads.get(row).active));
                prefs.setSetting("Payloads", payloads);
            }
            else if ((Boolean) this.getValueAt(row, col) == false) {
                payloads.set(row, new Payload(payloads.get(row).content,true, payloads.get(row).active));
                prefs.setSetting("Payloads", payloads);
            }
        }

        if (col == 2){
            if ((Boolean) this.getValueAt(row, col) == true) {
                payloads.set(row, new Payload(payloads.get(row).content, payloads.get(row).isRegex, false));
                prefs.setSetting("Payloads", payloads);
            }
            else if ((Boolean) this.getValueAt(row, col) == false) {
                payloads.set(row, new Payload(payloads.get(row).content, payloads.get(row).isRegex, true));
                prefs.setSetting("Payloads", payloads);
            }
        }
    }
}
