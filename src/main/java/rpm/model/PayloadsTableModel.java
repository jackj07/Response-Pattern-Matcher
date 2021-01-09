package rpm.model;

import rpm.Payload;
import com.coreyd97.BurpExtenderUtilities.Preferences;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class PayloadsTableModel extends AbstractTableModel {

    private List<Payload> payloads;
    private Preferences prefs;
    public PayloadsTableModel(List<Payload> payloads, Preferences prefs){
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
            return !payloads.get(row).getContent().equals("/*");
        } else return col == 2;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch(columnIndex) {
            case 0:
                return payloads.get(rowIndex).getContent();
            case 1:
                return payloads.get(rowIndex).getIsRegex();
            case 2:
                return payloads.get(rowIndex).getActive();
            default:
                return payloads.get(rowIndex).getContent();
        }
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if(row > payloads.size())return;
        super.setValueAt(value, row, col);

        if (col == 1) {
            if ((Boolean) this.getValueAt(row, col)) {
                payloads.set(row, new Payload(payloads.get(row).getContent(),false, payloads.get(row).getActive()));
                prefs.setSetting("Payloads", payloads);
            }
            else if (!(Boolean) this.getValueAt(row, col)) {
                payloads.set(row, new Payload(payloads.get(row).getContent(),true, payloads.get(row).getActive()));
                prefs.setSetting("Payloads", payloads);
            }
        }

        if (col == 2){
            if ((Boolean) this.getValueAt(row, col)) {
                payloads.set(row, new Payload(payloads.get(row).getContent(), payloads.get(row).getIsRegex(), false));
                prefs.setSetting("Payloads", payloads);
            }
            else if (!(Boolean) this.getValueAt(row, col)) {
                payloads.set(row, new Payload(payloads.get(row).getContent(), payloads.get(row).getIsRegex(), true));
                prefs.setSetting("Payloads", payloads);
            }
        }
    }
}
