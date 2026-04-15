import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public final class WorkflowChainTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "Chain",
            "Steps",
            "Score",
            "Highlights",
            "Rationale"
    };

    private final List<WorkflowGraphService.ChainView> rows = new ArrayList<>();

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
        return switch (columnIndex) {
            case 1 -> Integer.class;
            case 2 -> Long.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        WorkflowGraphService.ChainView row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.path();
            case 1 -> row.steps();
            case 2 -> row.score();
            case 3 -> row.highlights();
            case 4 -> row.rationale();
            default -> "";
        };
    }

    public void setRows(List<WorkflowGraphService.ChainView> nextRows) {
        rows.clear();
        rows.addAll(nextRows);
        fireTableDataChanged();
    }

    public WorkflowGraphService.ChainView rowAt(int rowIndex) {
        return rows.get(rowIndex);
    }
}
