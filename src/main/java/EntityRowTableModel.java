import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class EntityRowTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "Entity",
            "Type",
            "Risk",
            "Observations",
            "Methods",
            "Contexts",
            "Produced By",
            "Consumed By",
            "First Seen",
            "Last Seen"
    };

    private final List<EntityStoreService.EntityRow> rows = new ArrayList<>();

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
            case 3 -> Long.class;
            case 4, 5, 6, 7 -> Integer.class;
            case 8, 9 -> Instant.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        EntityStoreService.EntityRow row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.preview();
            case 1 -> row.entityType().displayName();
            case 2 -> row.riskDisplay();
            case 3 -> row.observations();
            case 4 -> row.uniqueMethods();
            case 5 -> row.authContexts();
            case 6 -> row.producerMethods();
            case 7 -> row.consumerMethods();
            case 8 -> row.firstSeen();
            case 9 -> row.lastSeen();
            default -> "";
        };
    }

    public void setRows(List<EntityStoreService.EntityRow> nextRows) {
        rows.clear();
        rows.addAll(nextRows);
        fireTableDataChanged();
    }

    public EntityStoreService.EntityRow rowAt(int rowIndex) {
        return rows.get(rowIndex);
    }
}
