package com.methodminer.ui;

import com.methodminer.comparison.RoleComparisonEngine;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.core.events.*;
import com.methodminer.payload.*;
import com.methodminer.risk.RiskSignalGenerator;
import com.methodminer.risk.RiskSignalResult;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Payloads panel displaying assembled payload candidates for authorization testing.
 *
 * <p>Auto-regenerates when surface, session, or risk signal events occur.
 * Provides copy buttons for body, HTTP request, and cURL command.
 */
public final class PayloadsPanel extends JPanel {

    private final EventBus eventBus;
    private final PayloadAssembler assembler;
    private final RoleComparisonEngine comparisonEngine;
    private final RiskSignalGenerator signalGenerator;
    private final PayloadTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<PayloadTableModel> sorter;
    private final JTabbedPane detailTabs;
    private final JTextArea bodyArea;
    private final JTextArea httpArea;
    private final JTextArea curlArea;
    private final JTextArea variablesArea;
    private final JTextArea stepsArea;
    private final JComboBox<String> typeFilter;
    private final JComboBox<String> protocolFilter;
    private final JTextField searchField;
    private final JLabel summaryLabel;

    public PayloadsPanel(EventBus eventBus, RoleComparisonEngine comparisonEngine,
                         RiskSignalGenerator signalGenerator, PayloadAssembler assembler) {
        super(new BorderLayout(4, 4));
        this.eventBus = Objects.requireNonNull(eventBus, "eventBus");
        this.assembler = Objects.requireNonNull(assembler, "assembler");
        this.comparisonEngine = Objects.requireNonNull(comparisonEngine, "comparisonEngine");
        this.signalGenerator = Objects.requireNonNull(signalGenerator, "signalGenerator");
        setBorder(BorderFactory.createTitledBorder("Payloads"));

        this.tableModel = new PayloadTableModel();
        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.getTableHeader().setReorderingAllowed(false);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onRowSelected();
        });

        // Column config
        table.getColumnModel().getColumn(0).setCellRenderer(new ScoreCellRenderer());
        table.getColumnModel().getColumn(0).setPreferredWidth(45);   // Score
        table.getColumnModel().getColumn(1).setPreferredWidth(120);  // Type
        table.getColumnModel().getColumn(2).setPreferredWidth(150);  // Operation
        table.getColumnModel().getColumn(3).setPreferredWidth(70);   // Protocol
        table.getColumnModel().getColumn(4).setPreferredWidth(70);   // Role
        table.getColumnModel().getColumn(5).setPreferredWidth(200);  // Title

        // Detail tabs
        bodyArea = createDetailArea();
        httpArea = createDetailArea();
        curlArea = createDetailArea();
        variablesArea = createDetailArea();
        stepsArea = createDetailArea();

        detailTabs = new JTabbedPane(JTabbedPane.TOP);
        detailTabs.addTab("Body", new JScrollPane(bodyArea));
        detailTabs.addTab("HTTP Request", new JScrollPane(httpArea));
        detailTabs.addTab("cURL", new JScrollPane(curlArea));
        detailTabs.addTab("Variables", new JScrollPane(variablesArea));
        detailTabs.addTab("Steps", new JScrollPane(stepsArea));

        // Toolbar with copy buttons
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        JButton refreshBtn = new JButton("Reassemble");
        refreshBtn.addActionListener(e -> reassemble());
        toolbar.add(refreshBtn);
        toolbar.addSeparator(new Dimension(6, 0));

        JButton copyBodyBtn = new JButton("Copy Body");
        copyBodyBtn.addActionListener(e -> copyToClipboard(bodyArea.getText()));
        toolbar.add(copyBodyBtn);

        JButton copyHttpBtn = new JButton("Copy HTTP");
        copyHttpBtn.addActionListener(e -> copyToClipboard(httpArea.getText()));
        toolbar.add(copyHttpBtn);

        JButton copyCurlBtn = new JButton("Copy cURL");
        copyCurlBtn.addActionListener(e -> copyToClipboard(curlArea.getText()));
        toolbar.add(copyCurlBtn);

        toolbar.addSeparator(new Dimension(6, 0));
        summaryLabel = new JLabel("No payloads assembled.");
        toolbar.add(summaryLabel);

        // Filter bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        filterBar.add(new JLabel("Type:"));
        typeFilter = new JComboBox<>(buildTypeOptions());
        typeFilter.addActionListener(e -> applyFilters());
        filterBar.add(typeFilter);

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

        // Layout
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                detailTabs
        );
        split.setResizeWeight(0.55);
        split.setOneTouchExpandable(true);
        split.setBorder(null);

        add(topPanel, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        // Subscribe to events
        eventBus.subscribe(SurfaceChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::reassemble));
        eventBus.subscribe(SessionChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::reassemble));

        // Initial assembly
        reassemble();
    }

    private void reassemble() {
        RoleComparisonResult comparison = comparisonEngine.compare();
        RiskSignalResult signals = signalGenerator.generate(comparison);
        PayloadAssemblyResult result = assembler.assemble(signals);
        tableModel.setData(result.candidates());
        updateSummary(result);
        applyFilters();
        eventBus.publish(new PayloadAssemblyChangedEvent(result));
    }

    private void updateSummary(PayloadAssemblyResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(result.totalCandidates()).append(" payloads | ");
        result.countsByType().forEach((type, count) ->
                sb.append(type.name()).append(": ").append(count).append("  "));
        summaryLabel.setText(sb.toString().trim());
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            clearDetails();
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        PayloadCandidate candidate = tableModel.getCandidate(modelRow);
        if (candidate == null) {
            clearDetails();
            return;
        }
        bodyArea.setText(candidate.rawBody());
        bodyArea.setCaretPosition(0);
        httpArea.setText(candidate.fullHttpRequest());
        httpArea.setCaretPosition(0);
        curlArea.setText(candidate.curlCommand());
        curlArea.setCaretPosition(0);
        variablesArea.setText(renderVariables(candidate));
        variablesArea.setCaretPosition(0);
        stepsArea.setText(candidate.summary() + "\n\n" + candidate.recommendedStep());
        stepsArea.setCaretPosition(0);
    }

    private void clearDetails() {
        bodyArea.setText("Select a payload to view details.");
        httpArea.setText("");
        curlArea.setText("");
        variablesArea.setText("");
        stepsArea.setText("");
    }

    private static String renderVariables(PayloadCandidate c) {
        if (c.variables().isEmpty()) return "No variables.";
        StringBuilder sb = new StringBuilder();
        sb.append("═══ Variables ═══\n\n");
        for (PayloadVariable v : c.variables()) {
            sb.append("Name:        ").append(v.name()).append('\n');
            sb.append("Placeholder: ").append(v.placeholder()).append('\n');
            sb.append("Description: ").append(v.description()).append('\n');
            sb.append("Source Role: ").append(v.sourceRole()).append('\n');
            if (!v.currentValue().isBlank()) {
                sb.append("Value:       ").append(v.currentValue()).append('\n');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private static void copyToClipboard(String text) {
        if (text != null && !text.isBlank()) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
        }
    }

    private void applyFilters() {
        List<RowFilter<PayloadTableModel, Integer>> filters = new ArrayList<>();

        String typeValue = (String) typeFilter.getSelectedItem();
        if (typeValue != null && !"ALL".equals(typeValue)) {
            filters.add(RowFilter.regexFilter("^" + typeValue + "$", 1));
        }

        String protoValue = (String) protocolFilter.getSelectedItem();
        if (protoValue != null && !"ALL".equals(protoValue)) {
            filters.add(RowFilter.regexFilter("^" + protoValue + "$", 3));
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

    private static JTextArea createDetailArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(6, 6, 6, 6));
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private static String[] buildTypeOptions() {
        PayloadCandidateType[] values = PayloadCandidateType.values();
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

    // ---- Table Model --------------------------------------------------------

    private static final class PayloadTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
                "Score", "Type", "Operation", "Protocol", "Role", "Title"
        };

        private List<PayloadCandidate> data = List.of();

        void setData(List<PayloadCandidate> candidates) {
            this.data = candidates == null ? List.of() : List.copyOf(candidates);
            fireTableDataChanged();
        }

        PayloadCandidate getCandidate(int row) {
            if (row < 0 || row >= data.size()) return null;
            return data.get(row);
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= data.size()) return "";
            PayloadCandidate c = data.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> c.score();
                case 1 -> c.candidateType().name();
                case 2 -> c.operationName();
                case 3 -> c.protocolKind().name();
                case 4 -> c.requiredRole();
                case 5 -> truncate(c.title(), 60);
                default -> "";
            };
        }

        private static String truncate(String text, int maxLen) {
            if (text == null) return "";
            return text.length() > maxLen ? text.substring(0, maxLen) + "…" : text;
        }
    }
}
