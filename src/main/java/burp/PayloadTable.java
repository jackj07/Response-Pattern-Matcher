package burp;

import javax.swing.*;
import javax.swing.table.TableModel;

public class PayloadTable extends JTable {
    private ContentController contentController;

    public PayloadTable(TableModel tableModel, ContentController contentController) {
        super(tableModel);
        this.contentController = contentController;
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        // show the log entry for the selected row
        contentController.setSelectedPayloadRow(row);
        super.changeSelection(row, col, toggle, extend);
    }
}
