import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class WorkflowNodeTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "Method",
            "Connections",
            "In",
            "Out",
            "Entry Point",
            "Privileged",
            "Entity IDs",
            "First Seen",
            "Last Seen"
    };

    private final List<WorkflowGraphService.MethodNodeView> rows = new ArrayList<>();

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
            case 1 -> Long.class;
            case 2, 3 -> Integer.class;
            case 4, 5 -> Boolean.class;
            case 7, 8 -> Instant.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        WorkflowGraphService.MethodNodeView row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.methodName();
            case 1 -> row.weightedConnections();
            case 2 -> row.inDegree();
            case 3 -> row.outDegree();
            case 4 -> row.entryPoint();
            case 5 -> row.privilegedEndpoint();
            case 6 -> row.entityHighlights();
            case 7 -> row.firstSeen();
            case 8 -> row.lastSeen();
            default -> "";
        };
    }

    public void setRows(List<WorkflowGraphService.MethodNodeView> nextRows) {
        rows.clear();
        rows.addAll(nextRows);
        fireTableDataChanged();
    }

    public WorkflowGraphService.MethodNodeView rowAt(int rowIndex) {
        return rows.get(rowIndex);
    }
}
