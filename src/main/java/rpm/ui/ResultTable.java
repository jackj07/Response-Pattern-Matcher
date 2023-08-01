package rpm.ui;

import burp.*;
import rpm.ResultEntry;
import rpm.controller.ContentController;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.event.InputEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

class ResultTable extends JTable {
    ExtenderPopupMenu menu;
    CellRenderer cellRenderer = new CellRenderer();

    @SuppressWarnings("deprecation")
    public ResultTable(TableModel tableModel, List<ResultEntry> results, ContentController contentController) {
        super(tableModel);
        this.setAutoCreateRowSorter(true);
        this.setDefaultRenderer(Object.class, cellRenderer);
        this.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
        menu = new ExtenderPopupMenu(tableModel, this, results, cellRenderer);
        DefaultListSelectionModel selectionModel = new DefaultListSelectionModel() {
            @Override
            public void setSelectionInterval(int index0, int index1) {
                try {
                    super.setSelectionInterval(index0, index1);
                    // Set currently displayed item for the selected row
                    if (index0 > results.size()) return; //try to prevent null pointers
                    ResultEntry resultsEntry = results.get(convertRowIndexToModel(index0));
                    IHttpRequestResponsePersisted requestResponsePersisted = resultsEntry.getRequestResponse();

                    //This guard is required because responseViewer.setMessage() is very resource intensive and causes Burp to slow down a lot on huge responses
                    if (contentController.getCurrentlyDisplayedItem() == null || contentController.getCurrentlyDisplayedItem() != requestResponsePersisted
                            || contentController.getRequestViewer().getMessage().length == 0) {
                        contentController.getRequestViewer().setMessage(requestResponsePersisted.getRequest(), true);

                        //The response sometimes doesn't exist for some requests. Guard here to prevent null pointer
                        if (requestResponsePersisted.getResponse() != null) {
                            contentController.getResponseViewer().setMessage(requestResponsePersisted.getResponse(), false);
                        } else {
                            contentController.getResponseViewer().setMessage(new byte[0], false);
                        }

                        contentController.setCurrentlyDisplayedItem(requestResponsePersisted);
                    }
                } catch (NullPointerException e1) { //debugging breakpoints
                    BurpExtender.stderror.println("A null pointer exception occurred in the result table:");
                    BurpExtender.stderror.println(e1);
                    e1.printStackTrace();
                } catch (Exception e2) {
                    BurpExtender.stderror.println("A exception occurred in the result table:");
                    BurpExtender.stderror.println(e2);
                    e2.printStackTrace();
                }
            }
        };
        this.setSelectionModel(selectionModel);

        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int rowIndex = getSelectedRow();
                if (rowIndex < 0)
                    return;
                if (isRightClick(e)) {
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    private static boolean isRightClick(MouseEvent e) {
        return (SwingUtilities.isRightMouseButton(e) ||
                e.getButton() == MouseEvent.BUTTON3 ||
                (System.getProperty("os.name").contains("Mac OS X") &&
                        (e.getModifiers() & InputEvent.BUTTON1_MASK) != 0 &&
                        (e.getModifiers() & InputEvent.CTRL_MASK) != 0));
    }

    public void setDefaultColumnSizes(){
        getColumnModel().getColumn(0).setPreferredWidth(5);
        getColumnModel().getColumn(1).setPreferredWidth(20);
        getColumnModel().getColumn(2).setPreferredWidth(400);
        getColumnModel().getColumn(3).setPreferredWidth(30);
        getColumnModel().getColumn(4).setPreferredWidth(600);
        setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
    }
}