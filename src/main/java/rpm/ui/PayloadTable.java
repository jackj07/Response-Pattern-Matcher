package rpm.ui;

import rpm.controller.ContentController;

import javax.swing.*;
import javax.swing.table.TableModel;

class PayloadTable extends JTable {
    private final ContentController contentController;

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

    public void setDefaultColumnSizes(){
        getColumnModel().getColumn(0).setPreferredWidth(420);
        getColumnModel().getColumn(1).setPreferredWidth(80);
        getColumnModel().getColumn(2).setPreferredWidth(80);
        setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
    }
}
