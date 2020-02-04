package burp;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.util.List;

public class ResultTable extends JTable
{
    public ResultTable(TableModel tableModel, List<ResultEntry> results, ContentController contentController)
    {
        super(tableModel);
        this.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
        this.setAutoCreateRowSorter(true);
        DefaultListSelectionModel selectionModel = new DefaultListSelectionModel(){
            @Override
            public void setSelectionInterval(int index0, int index1) {
                super.setSelectionInterval(index0, index1);
                // show the log entry for the selected row
                ResultEntry resultsEntry = results.get(convertRowIndexToModel(index0));
                IHttpRequestResponsePersisted requestResponsePersisted = resultsEntry.requestResponse;

                //This guard is required because responseViewer.setMessage() is very resource intensive and causes Burp to slow down a lot on huge responses
                if(contentController.getCurrentlyDisplayedItem() == null || contentController.getCurrentlyDisplayedItem() != requestResponsePersisted)
                {
                    contentController.getRequestViewer().setMessage(requestResponsePersisted.getRequest(), true);
                    contentController.getResponseViewer().setMessage(requestResponsePersisted.getResponse(), false);
                    contentController.setCurrentlyDisplayedItem(requestResponsePersisted);
                }
            }
        };
        this.setSelectionModel(selectionModel);
    }
}