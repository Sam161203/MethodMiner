import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class JsonRpcTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "Method",
            "Role",
            "Count",
            "Param Keys",
            "Unique Variants",
            "First Seen",
            "Last Seen"
    };

    private final List<JsonRpcIndex.MethodRow> rows = new ArrayList<>();
    private Set<String> newlyDiscoveredMethods = Set.of();
    private Map<String, RoleType> methodRoles = Map.of();

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
            case 4 -> Integer.class;
            case 5, 6 -> Instant.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        JsonRpcIndex.MethodRow row = rows.get(rowIndex);
        RoleType roleType = methodRoles.getOrDefault(row.methodName(), RoleType.UNKNOWN);
        return switch (columnIndex) {
            case 0 -> row.isRare() ? row.methodName() + " [RARE]" : row.methodName();
            case 1 -> roleType.displayName();
            case 2 -> row.count();
            case 3 -> row.paramKeys();
            case 4 -> row.uniqueVariants();
            case 5 -> row.firstSeen();
            case 6 -> row.lastSeen();
            default -> "";
        };
    }

    public void setRows(
            List<JsonRpcIndex.MethodRow> nextRows,
            Set<String> newlyDiscoveredMethods,
            Map<String, RoleType> methodRoles
    ) {
        rows.clear();
        rows.addAll(nextRows);
        this.newlyDiscoveredMethods = newlyDiscoveredMethods == null ? Set.of() : Set.copyOf(newlyDiscoveredMethods);
        this.methodRoles = methodRoles == null ? Map.of() : Map.copyOf(methodRoles);
        fireTableDataChanged();
    }

    public JsonRpcIndex.MethodRow rowAt(int modelRowIndex) {
        return rows.get(modelRowIndex);
    }

    public boolean isNewMethod(int modelRowIndex) {
        if (modelRowIndex < 0 || modelRowIndex >= rows.size()) {
            return false;
        }
        return newlyDiscoveredMethods.contains(rows.get(modelRowIndex).methodName());
    }
}
