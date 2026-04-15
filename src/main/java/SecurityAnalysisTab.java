import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SecurityAnalysisTab extends JPanel {
    private final MontoyaApi api;
    private final SecurityAnalyzerService analyzer;
    private final AuthContextStore authContextStore;
    private final JsonRpcCollector collector;
    private final ObjectMapper objectMapper;

    private final SecurityFindingTableModel tableModel = new SecurityFindingTableModel();
    private final JTable findingsTable = new JTable(tableModel);
    private final TableRowSorter<SecurityFindingTableModel> sorter = new TableRowSorter<>(tableModel);

    private final JTextField searchField = new JTextField(30);
    private final JLabel statusLabel = new JLabel("No findings yet");

    private final JTextArea findingDetailArea = buildTextArea();
    private final JComboBox<SampleSelection> sampleACombo = new JComboBox<>();
    private final JComboBox<SampleSelection> sampleBCombo = new JComboBox<>();

    private final DiffSectionPanel requestDiffPanel = new DiffSectionPanel("Request");
    private final DiffSectionPanel paramsDiffPanel = new DiffSectionPanel("Params");
    private final DiffSectionPanel responseDiffPanel = new DiffSectionPanel("Response");
    private final DiffSectionPanel schemaDiffPanel = new DiffSectionPanel("Normalized Schema");

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.ROOT)
            .withZone(ZoneId.systemDefault());

    public SecurityAnalysisTab(
            MontoyaApi api,
            SecurityAnalyzerService analyzer,
            AuthContextStore authContextStore,
            JsonRpcCollector collector,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.analyzer = analyzer;
        this.authContextStore = authContextStore;
        this.collector = collector;
        this.objectMapper = objectMapper;

        buildUi();
        wireEvents();
        refreshNow();
    }

    public void requestRefreshAsync() {
        if (refreshQueued.compareAndSet(false, true)) {
            SwingUtilities.invokeLater(() -> {
                refreshQueued.set(false);
                refreshNow();
            });
        }
    }

    private void buildUi() {
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.add(new JLabel("Search findings:"));
        controls.add(searchField);

        JButton refreshButton = new JButton("Refresh");
        JButton exportButton = new JButton("Export Method Bundle");
        JButton markReviewedButton = new JButton("Toggle Reviewed");

        refreshButton.addActionListener(e -> refreshNow());
        exportButton.addActionListener(e -> exportSelectedMethodBundle());
        markReviewedButton.addActionListener(e -> toggleReviewedForSelected());

        controls.add(refreshButton);
        controls.add(exportButton);
        controls.add(markReviewedButton);

        findingsTable.setFillsViewportHeight(true);
        findingsTable.setAutoCreateRowSorter(false);
        findingsTable.setRowSorter(sorter);
        findingsTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(220);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(100);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(160);
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(520);
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(140);
        findingsTable.getColumnModel().getColumn(6).setPreferredWidth(140);
        findingsTable.getColumnModel().getColumn(7).setPreferredWidth(80);
        findingsTable.getColumnModel().getColumn(8).setPreferredWidth(80);

        installRolePopupMenu();

        findingsTable.setDefaultRenderer(Object.class, new RiskAwareCellRenderer());
        findingsTable.setDefaultRenderer(Instant.class, new TimeCellRenderer());

        JScrollPane findingsScroll = new JScrollPane(findingsTable);
        findingsScroll.setBorder(BorderFactory.createTitledBorder("Findings"));

        JTabbedPaneWrapper detailTabs = new JTabbedPaneWrapper();
        detailTabs.addTab("Finding Details", new JScrollPane(findingDetailArea));
        detailTabs.addTab("Diff View", buildDiffViewPanel());

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, findingsScroll, detailTabs.component());
        mainSplit.setResizeWeight(0.5);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        footer.add(statusLabel, BorderLayout.WEST);

        add(controls, BorderLayout.NORTH);
        add(mainSplit, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    private JPanel buildDiffViewPanel() {
        JPanel root = new JPanel(new BorderLayout(8, 8));

        JPanel selectorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectorPanel.add(new JLabel("Sample A:"));
        selectorPanel.add(sampleACombo);
        selectorPanel.add(new JLabel("Sample B:"));
        selectorPanel.add(sampleBCombo);

        JButton compareButton = new JButton("Compare Selected Samples");
        compareButton.addActionListener(e -> refreshDiffPanels());
        selectorPanel.add(compareButton);

        JTabbedPaneWrapper diffTabs = new JTabbedPaneWrapper();
        diffTabs.addTab("Request Diff", requestDiffPanel);
        diffTabs.addTab("Params Diff", paramsDiffPanel);
        diffTabs.addTab("Response Diff", responseDiffPanel);
        diffTabs.addTab("Schema Diff", schemaDiffPanel);

        root.add(selectorPanel, BorderLayout.NORTH);
        root.add(diffTabs.component(), BorderLayout.CENTER);
        return root;
    }

    private void wireEvents() {
        tableModel.setReviewedChangeListener(analyzer::markReviewed);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyFilters();
            }
        });

        findingsTable.getSelectionModel().addListSelectionListener(event -> {
            if (event.getValueIsAdjusting()) {
                return;
            }
            updateSelectionDetails();
        });

        sampleACombo.addActionListener(e -> refreshDiffPanels());
        sampleBCombo.addActionListener(e -> refreshDiffPanels());

        installSampleRolePopup(sampleACombo);
        installSampleRolePopup(sampleBCombo);
    }

    private void refreshNow() {
        List<SecurityFinding> findings = analyzer.snapshotFindings();
        Map<String, RoleType> methodRoles = new HashMap<>();
        for (SecurityFinding finding : findings) {
            methodRoles.put(finding.method(), authContextStore.roleForMethod(finding.method()));
        }
        tableModel.setRows(findings, methodRoles);
        applyFilters();

        long reviewedCount = findings.stream().filter(SecurityFinding::reviewed).count();
        statusLabel.setText("Findings: " + findings.size() + " | Reviewed: " + reviewedCount);

        if (!findings.isEmpty() && findingsTable.getSelectedRow() < 0) {
            findingsTable.setRowSelectionInterval(0, 0);
        }

        updateSelectionDetails();
    }

    private void applyFilters() {
        String query = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);

        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends SecurityFindingTableModel, ? extends Integer> entry) {
                SecurityFinding finding = tableModel.rowAt(entry.getIdentifier());
                if (query.isBlank()) {
                    return true;
                }

                return finding.method().toLowerCase(Locale.ROOT).contains(query)
                        || authContextStore.roleForMethod(finding.method()).displayName().toLowerCase(Locale.ROOT).contains(query)
                        || finding.trigger().toLowerCase(Locale.ROOT).contains(query)
                        || finding.whyFlagged().toLowerCase(Locale.ROOT).contains(query)
                        || finding.riskDisplay().toLowerCase(Locale.ROOT).contains(query);
            }
        });
    }

    private void installRolePopupMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem markAdmin = new JMenuItem("Mark as Admin");
        JMenuItem markLowPriv = new JMenuItem("Mark as Low Priv");
        JMenuItem clearRole = new JMenuItem("Clear Role");

        markAdmin.addActionListener(e -> applyRoleToSelectedFinding(RoleType.ADMIN));
        markLowPriv.addActionListener(e -> applyRoleToSelectedFinding(RoleType.LOW_PRIV));
        clearRole.addActionListener(e -> applyRoleToSelectedFinding(RoleType.UNKNOWN));

        popup.add(markAdmin);
        popup.add(markLowPriv);
        popup.add(clearRole);

        findingsTable.setComponentPopupMenu(popup);
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent event) {
                selectPopupRow(event);
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                selectPopupRow(event);
            }
        });
    }

    private void selectPopupRow(MouseEvent event) {
        if (!event.isPopupTrigger()) {
            return;
        }
        int row = findingsTable.rowAtPoint(event.getPoint());
        if (row >= 0 && row < findingsTable.getRowCount()) {
            findingsTable.setRowSelectionInterval(row, row);
        }
    }

    private void installSampleRolePopup(JComboBox<SampleSelection> comboBox) {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem markAdmin = new JMenuItem("Mark sample context as Admin");
        JMenuItem markLowPriv = new JMenuItem("Mark sample context as Low Priv");
        JMenuItem clearRole = new JMenuItem("Clear sample context role");

        markAdmin.addActionListener(e -> applyRoleToSelectedSample(comboBox, RoleType.ADMIN));
        markLowPriv.addActionListener(e -> applyRoleToSelectedSample(comboBox, RoleType.LOW_PRIV));
        clearRole.addActionListener(e -> applyRoleToSelectedSample(comboBox, RoleType.UNKNOWN));

        popup.add(markAdmin);
        popup.add(markLowPriv);
        popup.add(clearRole);
        comboBox.setComponentPopupMenu(popup);
    }

    private void applyRoleToSelectedFinding(RoleType roleType) {
        SecurityFinding selected = selectedFinding();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a finding first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        boolean updated = authContextStore.setRoleForMethod(selected.method(), roleType);
        if (!updated) {
            JOptionPane.showMessageDialog(this, "No auth context is available yet for the selected method.", "Role update unavailable", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        refreshNow();
    }

    private void applyRoleToSelectedSample(JComboBox<SampleSelection> comboBox, RoleType roleType) {
        SampleSelection selected = (SampleSelection) comboBox.getSelectedItem();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a sample first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String contextKey = selected.sample.contextKey();
        boolean updated = authContextStore.setRoleForContextKey(contextKey, roleType);
        if (!updated) {
            JOptionPane.showMessageDialog(this, "Selected sample has no stored context key.", "Role update unavailable", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        refreshNow();
    }

    private void updateSelectionDetails() {
        SecurityFinding selectedFinding = selectedFinding();
        if (selectedFinding == null) {
            findingDetailArea.setText("");
            setSampleSelections(List.of());
            clearDiffPanels();
            return;
        }

        Optional<SecurityAnalyzerService.MethodSecurityDetails> detailsOptional = analyzer.snapshotMethodDetails(selectedFinding.method());
        if (detailsOptional.isEmpty()) {
            findingDetailArea.setText("No method-level security details available for this finding yet.");
            setSampleSelections(List.of());
            clearDiffPanels();
            return;
        }

        SecurityAnalyzerService.MethodSecurityDetails details = detailsOptional.get();

        try {
            ObjectNode root = details.toJson(objectMapper);
            root.put("selectedFindingId", selectedFinding.findingId());
            root.put("selectedTrigger", selectedFinding.trigger());
            root.put("selectedWhyFlagged", selectedFinding.whyFlagged());
            findingDetailArea.setText(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root));
        } catch (Exception ex) {
            findingDetailArea.setText("Unable to render finding details: " + ex.getMessage());
        }

        setSampleSelections(details.samples());
        refreshDiffPanels();
    }

    private void setSampleSelections(List<SecurityAnalyzerService.SampleView> samples) {
        DefaultComboBoxModel<SampleSelection> modelA = new DefaultComboBoxModel<>();
        DefaultComboBoxModel<SampleSelection> modelB = new DefaultComboBoxModel<>();

        for (int i = 0; i < samples.size(); i++) {
            SecurityAnalyzerService.SampleView sample = samples.get(i);
            SampleSelection selection = new SampleSelection(sample);
            modelA.addElement(selection);
            modelB.addElement(selection);
        }

        sampleACombo.setModel(modelA);
        sampleBCombo.setModel(modelB);

        if (samples.size() > 0) {
            sampleACombo.setSelectedIndex(0);
            sampleBCombo.setSelectedIndex(samples.size() > 1 ? 1 : 0);
        }
    }

    private void refreshDiffPanels() {
        SampleSelection left = (SampleSelection) sampleACombo.getSelectedItem();
        SampleSelection right = (SampleSelection) sampleBCombo.getSelectedItem();

        if (left == null || right == null) {
            clearDiffPanels();
            return;
        }

        SecurityAnalyzerService.SampleView leftSample = left.sample;
        SecurityAnalyzerService.SampleView rightSample = right.sample;

        requestDiffPanel.setValues(leftSample.requestRaw(), rightSample.requestRaw(), "Request diff");
        paramsDiffPanel.setValues(leftSample.paramsText(), rightSample.paramsText(), "Params diff");
        responseDiffPanel.setValues(leftSample.responseRaw(), rightSample.responseRaw(), "Response diff");
        schemaDiffPanel.setValues(leftSample.schemaText(), rightSample.schemaText(), "Normalized schema diff");
    }

    private void clearDiffPanels() {
        requestDiffPanel.setValues("", "", "Request diff");
        paramsDiffPanel.setValues("", "", "Params diff");
        responseDiffPanel.setValues("", "", "Response diff");
        schemaDiffPanel.setValues("", "", "Normalized schema diff");
    }

    private SecurityFinding selectedFinding() {
        int viewRow = findingsTable.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        int modelRow = findingsTable.convertRowIndexToModel(viewRow);
        return tableModel.rowAt(modelRow);
    }

    private void toggleReviewedForSelected() {
        SecurityFinding selected = selectedFinding();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a finding first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        analyzer.markReviewed(selected.findingId(), !selected.reviewed());
        refreshNow();
    }

    private void exportSelectedMethodBundle() {
        SecurityFinding selected = selectedFinding();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a finding first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        ObjectNode exportPayload;
        try {
            exportPayload = analyzer.buildManualExportBundle(selected.method());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not build export bundle: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export security review bundle");
        chooser.setSelectedFile(new File("jsonrpc-security-bundle-" + selected.method().replaceAll("[^a-zA-Z0-9_.-]", "_") + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String text = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(exportPayload);
            Files.writeString(destination.toPath(), text, StandardCharsets.UTF_8);
            analyzer.markExportedForMethod(selected.method());
            JOptionPane.showMessageDialog(this, "Security bundle exported to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
            refreshNow();
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting security bundle.", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static JTextArea buildTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private final class RiskAwareCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int column
        ) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (isSelected) {
                return component;
            }

            int modelRow = table.convertRowIndexToModel(row);
            SecurityFinding finding = tableModel.rowAt(modelRow);

            switch (finding.riskLevel()) {
                case CRITICAL -> component.setBackground(new Color(255, 225, 225));
                case HIGH -> component.setBackground(new Color(255, 238, 220));
                case MEDIUM -> component.setBackground(new Color(255, 250, 224));
                case LOW -> component.setBackground(UIManager.getColor("Table.background"));
            }

            if (column == 1) {
                RoleType roleType = authContextStore.roleForMethod(finding.method());
                switch (roleType) {
                    case ADMIN -> component.setForeground(new Color(0, 128, 0));
                    case LOW_PRIV -> component.setForeground(new Color(194, 112, 0));
                    case UNKNOWN -> component.setForeground(new Color(120, 120, 120));
                }
            } else {
                component.setForeground(UIManager.getColor("Table.foreground"));
            }

            return component;
        }
    }

    private final class TimeCellRenderer extends DefaultTableCellRenderer {
        @Override
        protected void setValue(Object value) {
            if (value instanceof Instant instant) {
                setText(timeFormatter.format(instant));
            } else {
                setText("");
            }
        }
    }

    private static final class SampleSelection {
        private final SecurityAnalyzerService.SampleView sample;

        private SampleSelection(SecurityAnalyzerService.SampleView sample) {
            this.sample = sample;
        }

        @Override
        public String toString() {
            return sample.label() + " [" + sample.roleTag() + "]";
        }
    }

    private static final class DiffSectionPanel extends JPanel {
        private final JTextArea leftArea = buildTextArea();
        private final JTextArea rightArea = buildTextArea();
        private final JTextArea summaryArea = buildTextArea();

        private DiffSectionPanel(String title) {
            super(new BorderLayout(6, 6));
            setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

            JScrollPane leftScroll = new JScrollPane(leftArea);
            leftScroll.setBorder(BorderFactory.createTitledBorder(title + " A"));
            JScrollPane rightScroll = new JScrollPane(rightArea);
            rightScroll.setBorder(BorderFactory.createTitledBorder(title + " B"));

            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightScroll);
            splitPane.setResizeWeight(0.5);

            JScrollPane summaryScroll = new JScrollPane(summaryArea);
            summaryScroll.setBorder(BorderFactory.createTitledBorder("Difference summary"));
            summaryScroll.setPreferredSize(new java.awt.Dimension(100, 140));

            add(splitPane, BorderLayout.CENTER);
            add(summaryScroll, BorderLayout.SOUTH);
        }

        private void setValues(String leftText, String rightText, String label) {
            leftArea.setText(leftText == null ? "" : leftText);
            rightArea.setText(rightText == null ? "" : rightText);
            summaryArea.setText(TextDiffUtil.summarizeDifferences(leftText, rightText, label));
        }
    }

    private static final class JTabbedPaneWrapper {
        private final javax.swing.JTabbedPane tabbedPane = new javax.swing.JTabbedPane();

        private void addTab(String title, Component component) {
            tabbedPane.addTab(title, component);
        }

        private Component component() {
            return tabbedPane;
        }
    }
}
