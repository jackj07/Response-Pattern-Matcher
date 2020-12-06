package burp;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ExtenderPopupMenu extends JPopupMenu {
    private JMenu highlightIdentical;
    private JMenuItem highlightBLUE;
    private JMenuItem highlightGREEN;
    private JMenuItem highlightRED;
    private JMenuItem highlightORANGE;
    private JMenuItem highlightCYAN;
    private JMenuItem highlightYELLOW;
    private JMenuItem highlightMAGENTA;
    private JMenuItem highlightPINK;
    private JMenuItem removeHighlight;
    private JMenu export;
    private JMenuItem exportHighlighted;
    private JMenuItem exportSelected;
    private JMenuItem exportAll;
    private JMenu delete;
    private JMenuItem deleteSelected;
    private JMenuItem deleteHighlighted;
    private JMenuItem deleteAll;

    private ResultsTableModel model;
    private JTable table;
    private List<ResultEntry> results;
    private CellRenderer cellRenderer;

    JSONParser parser = new JSONParser();

    public ExtenderPopupMenu(TableModel model_, JTable table_, List<ResultEntry> results_, CellRenderer cellRenderer_) {
        this.model = (ResultsTableModel)model_;
        this.table = table_;
        this.results = results_;
        this.cellRenderer = cellRenderer_;

        cellRenderer.setHighlightColor(table.getSelectionBackground());

        highlightIdentical = new JMenu("Highlight Identical Matches");
        highlightBLUE = new JMenuItem("Blue");
        highlightIdentical.add(highlightBLUE);
        highlightGREEN = new JMenuItem("Green");
        highlightIdentical.add(highlightGREEN);
        highlightRED = new JMenuItem("Red");
        highlightIdentical.add(highlightRED);
        highlightORANGE = new JMenuItem("Orange");
        highlightIdentical.add(highlightORANGE);
        highlightCYAN = new JMenuItem("Cyan");
        highlightIdentical.add(highlightCYAN);
        highlightYELLOW = new JMenuItem("Yellow");
        highlightIdentical.add(highlightYELLOW);
        highlightMAGENTA = new JMenuItem("Magenta");
        highlightIdentical.add(highlightMAGENTA);
        highlightPINK = new JMenuItem("Pink");
        highlightIdentical.add(highlightPINK);
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

        highlightBLUE.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.BLUE);
            }
        });

        highlightGREEN.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.GREEN);
            }
        });

        highlightRED.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.RED);
            }
        });

        highlightORANGE.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.ORANGE);
            }
        });

        highlightCYAN.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.CYAN);
            }
        });

        highlightYELLOW.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.YELLOW);
            }
        });

        highlightMAGENTA.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.MAGENTA);
            }
        });

        highlightPINK.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                highlightColour(Color.PINK);
            }
        });

        removeHighlight.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ResultEntry selectedResult = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
                if(selectedResult.getColor() != null) {
                    Color colourToClear = selectedResult.getColor();
                    for (ResultEntry result : results)if (result.getColor() == colourToClear)result.setColor(null);
                    model.fireTableDataChanged();
                    cellRenderer.setResults(results);
                    table.repaint();
                }
            }
        });

        exportSelected.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if(selectedRows.length > 0){
                    ArrayList<ResultEntry> results_to_export = new ArrayList<>();
                    for(int selectedRow : selectedRows)results_to_export.add(results.get(table.convertRowIndexToModel(selectedRow)));
                    if(!results_to_export.isEmpty())parser.writeResultsToFile(selectFile(),results_to_export);
                }
            }
        });

        exportHighlighted.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ResultEntry selectedResult = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
                if(selectedResult.getColor() != null) {
                    ArrayList<ResultEntry> results_to_export = new ArrayList<>();
                    Color colourToExport = selectedResult.getColor();
                    for (ResultEntry result : results)if(result.getColor() == colourToExport)results_to_export.add(result);
                    if(!results_to_export.isEmpty())parser.writeResultsToFile(selectFile(),results_to_export);
                }
            }
        });

        exportAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parser.writeResultsToFile(selectFile(),new ArrayList<ResultEntry>(results));//convert back from Collection.syncList
            }
        });

        deleteSelected.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if(selectedRows.length > 0){
                    List<ResultEntry> results_to_remove = new ArrayList<>();
                    for(int selectedRow : selectedRows)results_to_remove.add(results.get(table.convertRowIndexToModel(selectedRow)));

                    if(!results_to_remove.isEmpty()) {
                        for(ResultEntry resultToRemove : results_to_remove){
                            results.remove(resultToRemove);
                            model.fireTableRowsDeleted(results.indexOf(resultToRemove),results.indexOf(resultToRemove));
                        }
                        cellRenderer.setResults(results);
                        table.repaint();
                    }
                }
            }
        });

        deleteHighlighted.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ResultEntry selectedResult = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
                if(selectedResult.getColor() != null) {
                    List<ResultEntry> results_to_remove = new ArrayList<>();
                    Color colourToDelete = selectedResult.getColor();
                    for (ResultEntry result : results)if (result.getColor() == colourToDelete)results_to_remove.add(result);

                    if(!results_to_remove.isEmpty()) {
                        for(ResultEntry resultToRemove : results_to_remove){
                            results.remove(resultToRemove);
                            model.fireTableRowsDeleted(results.indexOf(resultToRemove),results.indexOf(resultToRemove));
                        }
                        cellRenderer.setResults(results);
                        table.repaint();
                    }
                }
            }
        });

        deleteAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int resultsSize = results.size()-1;
                results.clear();
                model.fireTableRowsDeleted(0,resultsSize);
                cellRenderer.setResults(results);
                table.repaint();
            }
        });
    }

    private void highlightColour(Color c){
        ResultEntry selectedResult = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
        for (ResultEntry result : results)if(result.getRequestResponse().equals(selectedResult.getRequestResponse()))result.setColor(c);
        model.fireTableDataChanged();
        cellRenderer.setResults(results);
        table.repaint(); //This calls getTableCellRendererComponent
    }

    private File selectFile(){
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.showSaveDialog(null);
        return fileChooser.getSelectedFile();
    }
}
