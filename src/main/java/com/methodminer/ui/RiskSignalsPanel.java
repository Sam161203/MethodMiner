package com.methodminer.ui;

import com.methodminer.comparison.RoleComparisonEngine;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.core.events.EventBus;
import com.methodminer.core.events.RiskSignalChangedEvent;
import com.methodminer.core.events.SessionChangedEvent;
import com.methodminer.core.events.SurfaceChangedEvent;
import com.methodminer.risk.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Risk signals panel that displays ranked security analysis results.
 *
 * <p>Auto-regenerates signals when surface, session, or comparison events occur.
 * Provides filtering by severity, category, protocol, and free-text search.
 * Selecting a signal shows a detailed explanation with evidence and recommended actions.
 */
public final class RiskSignalsPanel extends JPanel {

    private final RiskSignalGenerator generator;
    private final RoleComparisonEngine comparisonEngine;
    private final EventBus eventBus;
    private final RiskSignalTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<RiskSignalTableModel> sorter;
    private final JTextArea detailsArea;
    private final JComboBox<String> severityFilter;
    private final JComboBox<String> categoryFilter;
    private final JComboBox<String> protocolFilter;
    private final JTextField searchField;
    private final JLabel summaryLabel;

    public RiskSignalsPanel(EventBus eventBus, RoleComparisonEngine comparisonEngine,
                            RiskSignalGenerator generator) {
        super(new BorderLayout(4, 4));
        this.eventBus = Objects.requireNonNull(eventBus, "eventBus");
        this.comparisonEngine = Objects.requireNonNull(comparisonEngine, "comparisonEngine");
        this.generator = Objects.requireNonNull(generator, "generator");
        setBorder(BorderFactory.createTitledBorder("Risk Signals"));

        this.tableModel = new RiskSignalTableModel();
        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.getTableHeader().setReorderingAllowed(false);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onRowSelected();
        });

        // Column renderers
        table.getColumnModel().getColumn(0).setCellRenderer(new ScoreCellRenderer());
        table.getColumnModel().getColumn(1).setCellRenderer(new SeverityCellRenderer());
        table.getColumnModel().getColumn(0).setPreferredWidth(45);   // Score
        table.getColumnModel().getColumn(1).setPreferredWidth(65);   // Severity
        table.getColumnModel().getColumn(2).setPreferredWidth(140);  // Category
        table.getColumnModel().getColumn(3).setPreferredWidth(150);  // Operation
        table.getColumnModel().getColumn(4).setPreferredWidth(80);   // Coverage
        table.getColumnModel().getColumn(5).setPreferredWidth(70);   // Protocol
        table.getColumnModel().getColumn(6).setPreferredWidth(120);  // Host
        table.getColumnModel().getColumn(7).setPreferredWidth(180);  // Action

        // Details area
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setBorder(new EmptyBorder(6, 6, 6, 6));
        detailsArea.setText("Select a signal to view details.");

        // Toolbar
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        JButton refreshBtn = new JButton("Regenerate");
        refreshBtn.addActionListener(e -> regenerate());
        toolbar.add(refreshBtn);
        toolbar.addSeparator(new Dimension(8, 0));
        summaryLabel = new JLabel("No signals generated.");
        toolbar.add(summaryLabel);

        // Filter bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        filterBar.add(new JLabel("Severity:"));
        severityFilter = new JComboBox<>(new String[]{"ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
        severityFilter.addActionListener(e -> applyFilters());
        filterBar.add(severityFilter);

        filterBar.add(new JLabel("Category:"));
        categoryFilter = new JComboBox<>(buildCategoryOptions());
        categoryFilter.addActionListener(e -> applyFilters());
        filterBar.add(categoryFilter);

        filterBar.add(new JLabel("Protocol:"));
        protocolFilter = new JComboBox<>(new String[]{"ALL", "JSON_RPC", "GRAPHQL"});
        protocolFilter.addActionListener(e -> applyFilters());
        filterBar.add(protocolFilter);

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
        split.setResizeWeight(0.65);
        split.setOneTouchExpandable(true);
        split.setBorder(null);

        add(topPanel, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        // Subscribe to events for auto-regeneration
        eventBus.subscribe(SurfaceChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::regenerate));
        eventBus.subscribe(SessionChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::regenerate));

        // Initial generation
        regenerate();
    }

    private void regenerate() {
        RoleComparisonResult comparison = comparisonEngine.compare();
        RiskSignalResult result = generator.generate(comparison);
        tableModel.setData(result.signals());
        updateSummary(result);
        applyFilters();
        eventBus.publish(new RiskSignalChangedEvent(result));
    }

    private void updateSummary(RiskSignalResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(result.totalSignals()).append(" signals | ");
        result.countsBySeverity().forEach((sev, count) ->
                sb.append(sev.name()).append(": ").append(count).append("  "));
        summaryLabel.setText(sb.toString().trim());
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailsArea.setText("Select a signal to view details.");
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        RiskSignal signal = tableModel.getSignal(modelRow);
        if (signal == null) {
            detailsArea.setText("No data.");
            return;
        }
        detailsArea.setText(renderDetails(signal));
        detailsArea.setCaretPosition(0);
    }

    private static String renderDetails(RiskSignal s) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══ ").append(s.title()).append(" ═══\n\n");

        sb.append("Score:       ").append(s.score()).append("/100\n");
        sb.append("Severity:    ").append(s.severity()).append('\n');
        sb.append("Confidence:  ").append(s.confidence()).append('\n');
        sb.append("Category:    ").append(s.category()).append('\n');
        sb.append("Protocol:    ").append(s.protocolKind()).append('\n');
        sb.append("Host:        ").append(s.host()).append('\n');
        sb.append("Endpoint:    ").append(s.endpointPath()).append('\n');
        sb.append("Coverage:    ").append(s.coverageStatus()).append('\n');
        sb.append('\n');

        sb.append("── Why This Signal ──\n");
        sb.append(s.summary()).append("\n\n");

        sb.append("── Evidence ──\n");
        for (String ref : s.evidenceRefs()) {
            sb.append("  • ").append(ref).append('\n');
        }
        sb.append('\n');

        if (!s.parameters().isEmpty()) {
            sb.append("── Parameters ──\n");
            s.parameters().stream().sorted().forEach(p -> sb.append("  • ").append(p).append('\n'));
            sb.append('\n');
        }

        sb.append("── Recommended Next Step ──\n");
        sb.append(s.recommendedAction()).append('\n');

        return sb.toString();
    }

    private void applyFilters() {
        List<RowFilter<RiskSignalTableModel, Integer>> filters = new ArrayList<>();

        String sevValue = (String) severityFilter.getSelectedItem();
        if (sevValue != null && !"ALL".equals(sevValue)) {
            filters.add(RowFilter.regexFilter("^" + sevValue + "$", 1));
        }

        String catValue = (String) categoryFilter.getSelectedItem();
        if (catValue != null && !"ALL".equals(catValue)) {
            filters.add(RowFilter.regexFilter("^" + catValue + "$", 2));
        }

        String protoValue = (String) protocolFilter.getSelectedItem();
        if (protoValue != null && !"ALL".equals(protoValue)) {
            filters.add(RowFilter.regexFilter("^" + protoValue + "$", 5));
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

    private static String[] buildCategoryOptions() {
        RiskSignalCategory[] values = RiskSignalCategory.values();
        String[] options = new String[values.length + 1];
        options[0] = "ALL";
        for (int i = 0; i < values.length; i++) {
            options[i + 1] = values[i].name();
        }
        return options;
    }

    // ---- Score Cell Renderer ------------------------------------------------

    private static final class ScoreCellRenderer extends DefaultTableCellRenderer {
        ScoreCellRenderer() { setHorizontalAlignment(RIGHT); }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof Integer score) {
                if (score >= 80) c.setForeground(new Color(200, 40, 40));
                else if (score >= 60) c.setForeground(new Color(200, 120, 20));
                else if (score >= 35) c.setForeground(new Color(160, 160, 20));
                else c.setForeground(table.getForeground());
            }
            return c;
        }
    }

    // ---- Severity Cell Renderer ---------------------------------------------

    private static final class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String sev) {
                switch (sev) {
                    case "CRITICAL" -> c.setForeground(new Color(200, 40, 40));
                    case "HIGH" -> c.setForeground(new Color(200, 120, 20));
                    case "MEDIUM" -> c.setForeground(new Color(160, 160, 20));
                    case "LOW" -> c.setForeground(Color.GRAY);
                    default -> c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    // ---- Table Model --------------------------------------------------------

    private static final class RiskSignalTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
                "Score", "Severity", "Category", "Operation", "Coverage",
                "Protocol", "Host", "Recommended Action"
        };

        private List<RiskSignal> data = List.of();

        void setData(List<RiskSignal> signals) {
            this.data = signals == null ? List.of() : List.copyOf(signals);
            fireTableDataChanged();
        }

        RiskSignal getSignal(int row) {
            if (row < 0 || row >= data.size()) return null;
            return data.get(row);
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Integer.class; // Score
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= data.size()) return "";
            RiskSignal s = data.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> s.score();
                case 1 -> s.severity().name();
                case 2 -> s.category().name();
                case 3 -> s.operationName();
                case 4 -> s.coverageStatus().name();
                case 5 -> s.protocolKind().name();
                case 6 -> s.host();
                case 7 -> truncate(s.recommendedAction(), 80);
                default -> "";
            };
        }

        private static String truncate(String text, int maxLen) {
            if (text == null) return "";
            return text.length() > maxLen ? text.substring(0, maxLen) + "…" : text;
        }
    }
}
