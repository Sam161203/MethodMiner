import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public final class AttackSuggestionTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
        "Finding",
        "Category",
        "Host",
        "Priority",
        "Confidence",
        "Effectiveness",
        "Decision",
        "Method",
        "Attack Path",
        "Observation"
    };

    private final List<AttackSuggestion> rows = new ArrayList<>();

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AttackSuggestion row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.findingTitle();
            case 1 -> row.category();
            case 2 -> row.host();
            case 3 -> row.priorityDisplay();
            case 4 -> row.confidenceScore() + "/100 (" + row.confidenceDisplay() + ")";
            case 5 -> row.effectivenessScore() + "/100";
            case 6 -> row.verdictDisplay();
            case 7 -> row.primaryMethod();
            case 8 -> row.attackPath();
            case 9 -> row.observation();
            default -> "";
        };
    }

    public void setRows(List<AttackSuggestion> nextRows) {
        rows.clear();
        rows.addAll(nextRows);
        fireTableDataChanged();
    }

    public AttackSuggestion rowAt(int rowIndex) {
        return rows.get(rowIndex);
    }
}
