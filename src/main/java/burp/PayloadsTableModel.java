package burp;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class PayloadsTableModel extends AbstractTableModel {

    List<Payload> payloads;
    PayloadsTableModel(List<Payload> payloads){
        this.payloads = payloads;
    }

    @Override
    public int getRowCount() {
        return payloads.size();
    }

    @Override
    public int getColumnCount() { return 2; }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Payload";
            case 1:
                return "Is Regex";
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
            default:
                return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        if (col == 1) {
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
            default:
                return payloads.get(rowIndex).content;
        }
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        super.setValueAt(value, row, col);
        if (col == 1) {
            if ((Boolean) this.getValueAt(row, col) == true) {
                payloads.set(row, new Payload(payloads.get(row).content,false));
            }
            else if ((Boolean) this.getValueAt(row, col) == false) {
                payloads.set(row, new Payload(payloads.get(row).content,true));
            }
        }
    }
}
