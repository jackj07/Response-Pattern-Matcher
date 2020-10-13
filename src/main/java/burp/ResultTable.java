package burp;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeListener;
import java.util.List;

public class ResultTable extends JTable
{
    ExtenderPopupMenu menu;
    public ResultTable(TableModel tableModel, List<ResultEntry> results, ContentController contentController)
    {
        super(tableModel);
        this.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
        this.setAutoCreateRowSorter(true);
        menu = new ExtenderPopupMenu();
        DefaultListSelectionModel selectionModel = new DefaultListSelectionModel(){
            @Override
            public void setSelectionInterval(int index0, int index1) {
                super.setSelectionInterval(index0, index1);
                // show the log entry for the selected row
                ResultEntry resultsEntry = results.get(convertRowIndexToModel(index0));
                IHttpRequestResponsePersisted requestResponsePersisted = resultsEntry.requestResponse;

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

    class ExtenderPopupMenu extends JPopupMenu {
        JMenuItem highlightIdentical;
        JMenuItem removeHighlight;
        JMenu export;
        JMenuItem exportHighlighted;
        JMenuItem exportSelected;
        JMenuItem exportAll;
        JMenu delete;
        JMenuItem deleteSelected;
        JMenuItem deleteHighlighted;
        JMenuItem deleteAll;

        public ExtenderPopupMenu() {
            highlightIdentical = new JMenuItem("Highlight Identical Matches");
            add(highlightIdentical);

            removeHighlight = new JMenuItem("Remove Highlight");
            add(removeHighlight);

            export = new JMenu("Export");
            exportSelected = new JMenuItem("Selected");
            exportHighlighted = new JMenuItem("Highlighted Colour");
            exportAll = new JMenuItem("All");
            export.add(exportSelected);
            export.add(exportHighlighted);
            export.add(exportAll);
            add(export);

            delete = new JMenu("Delete");
            deleteSelected = new JMenuItem("Selected");
            deleteHighlighted = new JMenuItem("Highlighted Colour");
            deleteAll = new JMenuItem("All");
            delete.add(deleteSelected);
            delete.add(deleteHighlighted);
            delete.add(deleteAll);
            add(delete);

            highlightIdentical.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                    System.out.print("highlight identical clicked");

                    //Define colour that's not already been defined

                    //md5sum of item within row
                }
            });

            removeHighlight.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                }
            });

            exportSelected.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                }
            });

            exportHighlighted.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                }
            });

            exportAll.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO
                }
            });

            deleteSelected.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                }
            });

            deleteHighlighted.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                }
            });

            deleteAll.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    //TODO

                }
            });
        }
    }
}