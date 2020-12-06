package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.List;

public class CellRenderer extends DefaultTableCellRenderer{
    private Color highlightColour;
    private List<ResultEntry> results;
    public void setHighlightColor(Color colour){ this.highlightColour=colour; }
    public void setResults(List<ResultEntry>results){ this.results = results; }

    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column){
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        ResultEntry result = null;
        if(results != null)result = results.get(table.convertRowIndexToModel(row));

        if(result != null && result.getColor() != null){
            c.setBackground(result.getColor());
        }else{
            c.setBackground(table.getBackground());//no highlight
        }

        if(isSelected && highlightColour != null)c.setBackground(highlightColour);//Put burp selection highlight defaults back
        return c;
    }
}
