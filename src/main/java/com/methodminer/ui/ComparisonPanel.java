package com.methodminer.ui;

import com.methodminer.comparison.OperationRoleCoverage;
import com.methodminer.comparison.ParameterRoleCoverage;
import com.methodminer.comparison.RoleComparisonEngine;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.core.events.EventBus;
import com.methodminer.core.events.RoleComparisonChangedEvent;
import com.methodminer.core.events.SessionChangedEvent;
import com.methodminer.core.events.SurfaceChangedEvent;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Comparison panel that displays role coverage analysis results.
 *
 * <p>Auto-refreshes when surface or session events occur. Supports sorting,
 * filtering by status/protocol/host, and free-text search. Selecting a row
 * shows a detailed comparison summary.
 */
public final class ComparisonPanel extends JPanel {

    private final RoleComparisonEngine engine;
    private final EventBus eventBus;
    private final ComparisonTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<ComparisonTableModel> sorter;
    private final JTextArea detailsArea;
    private final JComboBox<String> statusFilter;
    private final JComboBox<String> protocolFilter;
    private final JTextField hostFilter;
    private final JTextField searchField;
    private final JLabel summaryLabel;

    public ComparisonPanel(EventBus eventBus, RoleComparisonEngine engine) {
        super(new BorderLayout(4, 4));
        this.eventBus = Objects.requireNonNull(eventBus, "eventBus");
        this.engine = Objects.requireNonNull(engine, "engine");
        setBorder(BorderFactory.createTitledBorder("Role Comparison"));

        this.tableModel = new ComparisonTableModel();
        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.getTableHeader().setReorderingAllowed(false);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onRowSelected();
        });

        // Status column renderer with color emphasis
        table.getColumnModel().getColumn(0).setCellRenderer(new StatusCellRenderer());
        table.getColumnModel().getColumn(0).setPreferredWidth(95);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);  // Protocol
        table.getColumnModel().getColumn(2).setPreferredWidth(130); // Host
        table.getColumnModel().getColumn(3).setPreferredWidth(160); // Operation
        table.getColumnModel().getColumn(4).setPreferredWidth(45);  // Admin
        table.getColumnModel().getColumn(5).setPreferredWidth(45);  // LowPriv
        table.getColumnModel().getColumn(6).setPreferredWidth(50);  // Unlabeled
        table.getColumnModel().getColumn(7).setPreferredWidth(120); // Parameters

        // Details area
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setBorder(new EmptyBorder(6, 6, 6, 6));
        detailsArea.setText("Select a row to view comparison details.");

        // Toolbar
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        JButton refreshBtn = new JButton("Recompute");
        refreshBtn.addActionListener(e -> recompute());
        toolbar.add(refreshBtn);
        toolbar.addSeparator(new Dimension(8, 0));
        summaryLabel = new JLabel("No comparison data.");
        toolbar.add(summaryLabel);

        // Filter bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        filterBar.add(new JLabel("Status:"));
        statusFilter = new JComboBox<>(new String[]{
                "ALL", "ADMIN_ONLY", "BOTH", "LOW_PRIV_ONLY", "UNLABELED", "UNKNOWN"});
        statusFilter.addActionListener(e -> applyFilters());
        filterBar.add(statusFilter);

        filterBar.add(new JLabel("Protocol:"));
        protocolFilter = new JComboBox<>(new String[]{"ALL", "JSON_RPC", "GRAPHQL"});
        protocolFilter.addActionListener(e -> applyFilters());
        filterBar.add(protocolFilter);

        filterBar.add(new JLabel("Host:"));
        hostFilter = new JTextField(10);
        hostFilter.addActionListener(e -> applyFilters());
        filterBar.add(hostFilter);

        filterBar.add(new JLabel("Search:"));
        searchField = new JTextField(10);
        searchField.addActionListener(e -> applyFilters());
        filterBar.add(searchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyFilters());
        filterBar.add(filterBtn);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbar, BorderLayout.NORTH);
        topPanel.add(filterBar, BorderLayout.SOUTH);

        // Layout: table on top, details on bottom
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                new JScrollPane(detailsArea)
        );
        split.setResizeWeight(0.7);
        split.setOneTouchExpandable(true);
        split.setBorder(null);

        add(topPanel, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        // Subscribe to events for auto-recompute
        eventBus.subscribe(SurfaceChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::recompute));
        eventBus.subscribe(SessionChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::recompute));

        // Initial computation
        recompute();
    }

    private void recompute() {
        RoleComparisonResult result = engine.compare();
        tableModel.setData(result.operationCoverages());
        updateSummary(result);
        applyFilters();
        eventBus.publish(new RoleComparisonChangedEvent(result));
    }

    private void updateSummary(RoleComparisonResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(result.totalOperations()).append(" ops, ");
        sb.append(result.totalSessions()).append(" sessions | ");
        for (var entry : result.countsByStatus().entrySet()) {
            sb.append(entry.getKey().name()).append(": ").append(entry.getValue()).append("  ");
        }
        summaryLabel.setText(sb.toString().trim());
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailsArea.setText("Select a row to view comparison details.");
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        OperationRoleCoverage coverage = tableModel.getCoverage(modelRow);
        if (coverage == null) {
            detailsArea.setText("No data.");
            return;
        }
        detailsArea.setText(renderDetails(coverage));
        detailsArea.setCaretPosition(0);
    }

    private static String renderDetails(OperationRoleCoverage c) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══ ").append(c.operationName()).append(" ═══\n\n");
        sb.append("Status:     ").append(c.status()).append('\n');
        sb.append("Protocol:   ").append(c.protocolKind()).append('\n');
        sb.append("Host:       ").append(c.host()).append('\n');
        sb.append("Endpoint:   ").append(c.endpointPath()).append('\n');
        sb.append("Admin:      ").append(c.adminSessionCount()).append(" session(s)\n");
        sb.append("Low-Priv:   ").append(c.lowPrivSessionCount()).append(" session(s)\n");
        sb.append("Unlabeled:  ").append(c.unlabeledSessionCount()).append(" session(s)\n\n");

        if (!c.parameterCoverage().isEmpty()) {
            sb.append("── Parameters ──\n");
            for (ParameterRoleCoverage p : c.parameterCoverage()) {
                sb.append("  ").append(p.name());
                sb.append(" [").append(p.status()).append("]");
                if (!p.typesByRole().isEmpty()) {
                    sb.append(" types: ");
                    p.typesByRole().forEach((role, types) ->
                            sb.append(role).append("=").append(types).append(" "));
                }
                sb.append('\n');
            }
        } else {
            sb.append("No parameter details available.\n");
        }

        return sb.toString();
    }

    private void applyFilters() {
        List<RowFilter<ComparisonTableModel, Integer>> filters = new ArrayList<>();

        String statusValue = (String) statusFilter.getSelectedItem();
        if (statusValue != null && !"ALL".equals(statusValue)) {
            filters.add(RowFilter.regexFilter("^" + statusValue + "$", 0));
        }

        String protocolValue = (String) protocolFilter.getSelectedItem();
        if (protocolValue != null && !"ALL".equals(protocolValue)) {
            filters.add(RowFilter.regexFilter("^" + protocolValue + "$", 1));
        }

        String hostText = hostFilter.getText().trim();
        if (!hostText.isBlank()) {
            filters.add(RowFilter.regexFilter("(?i)" + escapeRegex(hostText), 2));
        }

        String searchText = searchField.getText().trim();
        if (!searchText.isBlank()) {
            filters.add(RowFilter.regexFilter("(?i)" + escapeRegex(searchText)));
        }

        sorter.setRowFilter(filters.isEmpty() ? null : RowFilter.andFilter(filters));
    }

    private static String escapeRegex(String text) {
        return text.replaceAll("([\\\\\\[\\]{}()*+?.^$|])", "\\\\$1");
    }

    // ---- Status Cell Renderer ---------------------------------------------

    private static final class StatusCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String status) {
                switch (status) {
                    case "ADMIN_ONLY" -> c.setForeground(new Color(200, 60, 60));
                    case "LOW_PRIV_ONLY" -> c.setForeground(new Color(50, 140, 50));
                    case "BOTH" -> c.setForeground(new Color(50, 100, 200));
                    case "UNLABELED" -> c.setForeground(Color.GRAY);
                    default -> c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    // ---- Table Model -------------------------------------------------------

    private static final class ComparisonTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
                "Status", "Protocol", "Host", "Operation", "Admin", "LowPriv", "Unlabeled", "Parameters"
        };

        private List<OperationRoleCoverage> data = List.of();

        void setData(List<OperationRoleCoverage> coverages) {
            this.data = coverages == null ? List.of() : List.copyOf(coverages);
            fireTableDataChanged();
        }

        OperationRoleCoverage getCoverage(int row) {
            if (row < 0 || row >= data.size()) return null;
            return data.get(row);
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return switch (columnIndex) {
                case 4, 5, 6 -> Integer.class;
                default -> String.class;
            };
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= data.size()) return "";
            OperationRoleCoverage c = data.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> c.status().name();
                case 1 -> c.protocolKind().name();
                case 2 -> c.host();
                case 3 -> c.operationName();
                case 4 -> c.adminSessionCount();
                case 5 -> c.lowPrivSessionCount();
                case 6 -> c.unlabeledSessionCount();
                case 7 -> c.parameterNames().stream().sorted().collect(Collectors.joining(", "));
                default -> "";
            };
        }
    }
}
