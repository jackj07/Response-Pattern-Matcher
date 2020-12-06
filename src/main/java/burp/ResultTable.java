package burp;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

public class ResultTable extends JTable
{
    ExtenderPopupMenu menu;
    CellRenderer cellRenderer = new CellRenderer();
    public ResultTable(TableModel tableModel, List<ResultEntry> results, ContentController contentController)
    {
        super(tableModel);
        this.setAutoCreateRowSorter(true);
        this.setDefaultRenderer(Object.class, cellRenderer);
        this.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
        menu = new ExtenderPopupMenu(tableModel, this, results, cellRenderer);
        DefaultListSelectionModel selectionModel = new DefaultListSelectionModel(){
            @Override
            public void setSelectionInterval(int index0, int index1) {
                super.setSelectionInterval(index0, index1);
                // show the log entry for the selected row
                ResultEntry resultsEntry = results.get(convertRowIndexToModel(index0));
                IHttpRequestResponsePersisted requestResponsePersisted = resultsEntry.getRequestResponse();

                //This guard is required because responseViewer.setMessage() is very resource intensive and causes Burp to slow down a lot on huge responses
                if(contentController.getCurrentlyDisplayedItem() == null || contentController.getCurrentlyDisplayedItem() != requestResponsePersisted
                        || contentController.getRequestViewer().getMessage().length == 0)
                {
                    contentController.getRequestViewer().setMessage(requestResponsePersisted.getRequest(), true);

                    //The response sometimes doesn't exist for some requests. Guard here to prevent null pointer
                    if(requestResponsePersisted.getResponse() != null){
                        contentController.getResponseViewer().setMessage(requestResponsePersisted.getResponse(), false);
                    }else{
                        contentController.getResponseViewer().setMessage(new byte[0], false);
                    }

                    contentController.setCurrentlyDisplayedItem(requestResponsePersisted);
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
                e.getButton()==MouseEvent.BUTTON3 ||
                (System.getProperty("os.name").contains("Mac OS X") &&
                        (e.getModifiers() & e.BUTTON1_MASK) != 0 &&
                        (e.getModifiers() & e.CTRL_MASK) != 0));
    }
}