import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class WorkflowEdgeTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "From",
            "To",
            "Correlations",
            "Entity IDs",
            "Shared Values",
            "First Seen",
            "Last Seen"
    };

    private final List<WorkflowGraphService.EdgeView> rows = new ArrayList<>();

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
            case 2 -> Long.class;
            case 5, 6 -> Instant.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        WorkflowGraphService.EdgeView row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.sourceMethod();
            case 1 -> row.targetMethod();
            case 2 -> row.correlations();
            case 3 -> row.entityHighlights();
            case 4 -> row.sharedValues();
            case 5 -> row.firstSeen();
            case 6 -> row.lastSeen();
            default -> "";
        };
    }

    public void setRows(List<WorkflowGraphService.EdgeView> nextRows) {
        rows.clear();
        rows.addAll(nextRows);
        fireTableDataChanged();
    }

    public WorkflowGraphService.EdgeView rowAt(int rowIndex) {
        return rows.get(rowIndex);
    }
}
