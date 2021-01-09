package rpm.ui;

import burp.BurpExtender;
import rpm.model.ResultsTableModel;
import rpm.ResultEntry;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

class ExtenderPopupMenu extends JPopupMenu {
    private ResultsTableModel model;
    private ResultTable table;
    private List<ResultEntry> results;
    private CellRenderer cellRenderer;

    JSONParser parser = new JSONParser(BurpExtender.callbacks);

    public ExtenderPopupMenu(TableModel model_, ResultTable table_, List<ResultEntry> results_, CellRenderer cellRenderer_) {
        this.model = (ResultsTableModel)model_;
        this.table = table_;
        this.results = results_;
        this.cellRenderer = cellRenderer_;

        cellRenderer.setHighlightColor(table.getSelectionBackground());

        JMenu highlightIdentical = new JMenu("Highlight Identical Matches");
        JMenuItem highlightBLUE = new JMenuItem("Blue");
        highlightIdentical.add(highlightBLUE);
        JMenuItem highlightGREEN = new JMenuItem("Green");
        highlightIdentical.add(highlightGREEN);
        JMenuItem highlightRED = new JMenuItem("Red");
        highlightIdentical.add(highlightRED);
        JMenuItem highlightORANGE = new JMenuItem("Orange");
        highlightIdentical.add(highlightORANGE);
        JMenuItem highlightCYAN = new JMenuItem("Cyan");
        highlightIdentical.add(highlightCYAN);
        JMenuItem highlightYELLOW = new JMenuItem("Yellow");
        highlightIdentical.add(highlightYELLOW);
        JMenuItem highlightMAGENTA = new JMenuItem("Magenta");
        highlightIdentical.add(highlightMAGENTA);
        JMenuItem highlightPINK = new JMenuItem("Pink");
        highlightIdentical.add(highlightPINK);
        add(highlightIdentical);

        JMenuItem removeHighlight = new JMenuItem("Remove Highlight");
        add(removeHighlight);

        JMenu export = new JMenu("Export");
        JMenuItem exportSelected = new JMenuItem("Selected");
        JMenuItem exportHighlighted = new JMenuItem("Highlighted Colour");
        JMenuItem exportAll = new JMenuItem("All");
        export.add(exportSelected);
        export.add(exportHighlighted);
        export.add(exportAll);
        add(export);

        JMenu delete = new JMenu("Delete");
        JMenuItem deleteSelected = new JMenuItem("Selected");
        JMenuItem deleteHighlighted = new JMenuItem("Highlighted Colour");
        JMenuItem deleteAll = new JMenuItem("All");
        delete.add(deleteSelected);
        delete.add(deleteHighlighted);
        delete.add(deleteAll);
        add(delete);

        highlightBLUE.addActionListener(e -> highlightColour(Color.BLUE));
        highlightGREEN.addActionListener(e -> highlightColour(Color.GREEN));
        highlightRED.addActionListener(e -> highlightColour(Color.RED));
        highlightORANGE.addActionListener(e -> highlightColour(Color.ORANGE));
        highlightCYAN.addActionListener(e -> highlightColour(Color.CYAN));
        highlightYELLOW.addActionListener(e -> highlightColour(Color.YELLOW));
        highlightMAGENTA.addActionListener(e -> highlightColour(Color.MAGENTA));
        highlightPINK.addActionListener(e -> highlightColour(Color.PINK));

        removeHighlight.addActionListener(e -> {
            ResultEntry selectedResult = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
            if(selectedResult.getColor() != null) {
                Color colourToClear = selectedResult.getColor();
                for (ResultEntry result : results)if (result.getColor() == colourToClear)result.setColor(null);
                model.fireTableDataChanged();
                cellRenderer.setResults(results);
                table.repaint();
            }
        });

        exportSelected.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if(selectedRows.length > 0){
                ArrayList<ResultEntry> results_to_export = new ArrayList<>();
                for(int selectedRow : selectedRows)results_to_export.add(results.get(table.convertRowIndexToModel(selectedRow)));
                if(!results_to_export.isEmpty())parser.writeResultsToFile(selectFile(),results_to_export);
            }
        });

        exportHighlighted.addActionListener(e -> {
            ResultEntry selectedResult = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
            if(selectedResult.getColor() != null) {
                ArrayList<ResultEntry> results_to_export = new ArrayList<>();
                Color colourToExport = selectedResult.getColor();
                for (ResultEntry result : results)if(result.getColor() == colourToExport)results_to_export.add(result);
                if(!results_to_export.isEmpty())parser.writeResultsToFile(selectFile(),results_to_export);
            }
        });

        exportAll.addActionListener(e -> {
            parser.writeResultsToFile(selectFile(),new ArrayList<>(results));//convert back from Collection.syncList
        });

        deleteSelected.addActionListener(e -> {
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
                    table.setDefaultColumnSizes();
                }
            }
        });

        deleteHighlighted.addActionListener(e -> {
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
                    table.setDefaultColumnSizes();
                }
            }
        });

        deleteAll.addActionListener(e -> {
            int resultsSize = results.size()-1;
            results.clear();
            model.fireTableRowsDeleted(0,resultsSize);
            cellRenderer.setResults(results);
            table.repaint();
            table.setDefaultColumnSizes();
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
