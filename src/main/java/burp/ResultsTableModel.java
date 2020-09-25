package burp;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class ResultsTableModel extends AbstractTableModel {
    private List<ResultEntry> results;
    public ResultsTableModel(List<ResultEntry> results) {
        this.results=results;
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Tool";
            case 2:
                return "URL";
            case 3:
                return "Payload";
            case 4:
                return "Sample Extract";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if(columnIndex == 0)return Integer.class;
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ResultEntry resultEntry = results.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return resultEntry.number;
            case 1:
                return BurpExtender.callbacks.getToolName(resultEntry.tool);
            case 2:
                return resultEntry.url.toString();
            case 3:
                return resultEntry.payloadContent;
            case 4:
                return resultEntry.sampleExtract;
            default:
                return "";
        }
    }
}
