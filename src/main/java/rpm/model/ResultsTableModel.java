package rpm.model;

import rpm.ResponsePatternMatcher;
import rpm.ResultEntry;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class ResultsTableModel extends AbstractTableModel {
    private final List<ResultEntry> results;
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
        if(rowIndex > results.size()) return "";
        ResultEntry resultEntry = results.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return resultEntry.getNumber();
            case 1:
                return ResponsePatternMatcher.callbacks.getToolName(resultEntry.getTool());
            case 2:
                return resultEntry.getUrl().toString();
            case 3:
                return resultEntry.getPayloadContent();
            case 4:
                return resultEntry.getSampleExtract();
            default:
                return "";
        }
    }
}
