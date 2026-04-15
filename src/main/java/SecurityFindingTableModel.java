import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

public final class SecurityFindingTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "Method",
            "Role",
            "Risk",
            "Trigger",
            "Why flagged",
            "First seen",
            "Last seen",
            "Exported",
            "Reviewed"
    };

    private final List<SecurityFinding> rows = new ArrayList<>();
    private Map<String, RoleType> methodRoles = Map.of();
    private BiConsumer<String, Boolean> reviewedChangeListener;

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
            case 5, 6 -> Instant.class;
            case 7, 8 -> Boolean.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 8;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SecurityFinding finding = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> finding.method();
            case 1 -> methodRoles.getOrDefault(finding.method(), RoleType.UNKNOWN).displayName();
            case 2 -> finding.riskDisplay();
            case 3 -> finding.trigger();
            case 4 -> finding.whyFlagged();
            case 5 -> finding.firstSeen();
            case 6 -> finding.lastSeen();
            case 7 -> finding.exported();
            case 8 -> finding.reviewed();
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex != 8 || rowIndex < 0 || rowIndex >= rows.size()) {
            return;
        }

        boolean reviewed = aValue instanceof Boolean b && b;
        SecurityFinding original = rows.get(rowIndex);
        SecurityFinding updated = original.withReviewed(reviewed);
        rows.set(rowIndex, updated);
        fireTableRowsUpdated(rowIndex, rowIndex);

        if (reviewedChangeListener != null) {
            reviewedChangeListener.accept(original.findingId(), reviewed);
        }
    }

    public void setRows(List<SecurityFinding> findings, Map<String, RoleType> methodRoles) {
        rows.clear();
        rows.addAll(findings);
        this.methodRoles = methodRoles == null ? Map.of() : Map.copyOf(methodRoles);
        fireTableDataChanged();
    }

    public SecurityFinding rowAt(int row) {
        return rows.get(row);
    }

    public void setReviewedChangeListener(BiConsumer<String, Boolean> listener) {
        this.reviewedChangeListener = listener;
    }
}
