import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.BorderFactory;
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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public final class JsonRpcTab extends JPanel {
    private final MontoyaApi api;
    private final JsonRpcCollector collector;
    private final JsonRpcIndex index;
    private final AuthContextStore authContextStore;
    private final LogicHunterExportService exportService;
    private final ObjectMapper objectMapper;

    private final JsonRpcTableModel tableModel = new JsonRpcTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<JsonRpcTableModel> sorter = new TableRowSorter<>(tableModel);
    private final JsonRpcDetailPanel detailPanel = new JsonRpcDetailPanel();
    private final JTextField searchField = new JTextField(30);
    private final JComboBox<FilterOption> filterComboBox = new JComboBox<>(FilterOption.values());
    private final JLabel statsLabel = new JLabel("No records yet");

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);
    private final Set<String> previouslyKnownMethods = new HashSet<>();

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.ROOT)
            .withZone(ZoneId.systemDefault());

    public JsonRpcTab(
            MontoyaApi api,
            JsonRpcCollector collector,
            JsonRpcIndex index,
            AuthContextStore authContextStore,
            LogicHunterExportService exportService,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.collector = collector;
        this.index = index;
        this.authContextStore = authContextStore;
        this.exportService = exportService;
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
        controls.add(new JLabel("Search:"));
        controls.add(searchField);
        controls.add(new JLabel("Filter:"));
        controls.add(filterComboBox);

        JButton refreshButton = new JButton("Refresh");
        JButton exportButton = new JButton("Export Selected");
        JButton exportCurrentMethodButton = new JButton("Export Current Method Only");
        JButton exportAllButton = new JButton("Export All Data");
        JButton clearButton = new JButton("Clear / Reset");

        refreshButton.addActionListener(e -> refreshNow());
        exportButton.addActionListener(e -> exportSelectedRows());
        exportCurrentMethodButton.addActionListener(e -> exportCurrentMethodOnly());
        exportAllButton.addActionListener(e -> exportAllData());
        clearButton.addActionListener(e -> confirmAndClear());

        controls.add(refreshButton);
        controls.add(exportButton);
        controls.add(exportCurrentMethodButton);
        controls.add(exportAllButton);
        controls.add(clearButton);

        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(sorter);
        table.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(280);
        table.getColumnModel().getColumn(1).setPreferredWidth(110);
        table.getColumnModel().getColumn(3).setPreferredWidth(280);
        table.setDefaultRenderer(Object.class, new MethodCellRenderer());
        table.setDefaultRenderer(Instant.class, new TimeCellRenderer());
        installRolePopupMenu();

        JScrollPane tableScrollPane = new JScrollPane(table);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("Discovered JSON-RPC Methods"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, detailPanel);
        splitPane.setResizeWeight(0.45);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        footer.add(statsLabel, BorderLayout.WEST);

        add(controls, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    private void wireEvents() {
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

        filterComboBox.addActionListener(e -> applyFilters());

        table.getSelectionModel().addListSelectionListener(event -> {
            if (event.getValueIsAdjusting()) {
                return;
            }
            showSelectedDetails();
        });
    }

    private void refreshNow() {
        List<JsonRpcIndex.MethodRow> rows = index.snapshotMethodRows();
        Set<String> currentMethods = new HashSet<>();
        Set<String> newMethods = new HashSet<>();
        Map<String, RoleType> methodRoles = new HashMap<>();

        for (JsonRpcIndex.MethodRow row : rows) {
            currentMethods.add(row.methodName());
            methodRoles.put(row.methodName(), authContextStore.roleForMethod(row.methodName()));
            if (!previouslyKnownMethods.contains(row.methodName())) {
                newMethods.add(row.methodName());
            }
        }

        previouslyKnownMethods.clear();
        previouslyKnownMethods.addAll(currentMethods);

        tableModel.setRows(rows, newMethods, methodRoles);
        applyFilters();
        updateStatsLabel(index.snapshotStats());
        showSelectedDetails();
    }

    private void installRolePopupMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem markAdmin = new JMenuItem("Mark as Admin");
        JMenuItem markLowPriv = new JMenuItem("Mark as Low Priv");
        JMenuItem clearRole = new JMenuItem("Clear Role");

        markAdmin.addActionListener(e -> applyRoleToSelectedMethod(RoleType.ADMIN));
        markLowPriv.addActionListener(e -> applyRoleToSelectedMethod(RoleType.LOW_PRIV));
        clearRole.addActionListener(e -> applyRoleToSelectedMethod(RoleType.UNKNOWN));

        popupMenu.add(markAdmin);
        popupMenu.add(markLowPriv);
        popupMenu.add(clearRole);

        table.setComponentPopupMenu(popupMenu);
        table.addMouseListener(new MouseAdapter() {
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

        int row = table.rowAtPoint(event.getPoint());
        if (row >= 0 && row < table.getRowCount()) {
            table.setRowSelectionInterval(row, row);
        }
    }

    private void applyRoleToSelectedMethod(RoleType roleType) {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a method first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        JsonRpcIndex.MethodRow method = tableModel.rowAt(modelRow);

        boolean updated = authContextStore.setRoleForMethod(method.methodName(), roleType);
        if (!updated) {
            JOptionPane.showMessageDialog(
                    this,
                    "Unable to resolve an auth context for this method yet. Capture at least one request/response first.",
                    "Role update unavailable",
                    JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }

        refreshNow();
    }

    private void applyFilters() {
        FilterOption option = (FilterOption) filterComboBox.getSelectedItem();
        String query = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);

        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends JsonRpcTableModel, ? extends Integer> entry) {
                JsonRpcIndex.MethodRow row = tableModel.rowAt(entry.getIdentifier());

                if (!option.accept(row)) {
                    return false;
                }

                if (query.isBlank()) {
                    return true;
                }

                return row.methodName().toLowerCase(Locale.ROOT).contains(query)
                        || row.paramKeys().toLowerCase(Locale.ROOT).contains(query);
            }
        });
    }

    private void showSelectedDetails() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailPanel.clear();
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        JsonRpcIndex.MethodRow selected = tableModel.rowAt(modelRow);
        index.snapshotMethodDetails(selected.methodName())
                .ifPresentOrElse(
                        details -> detailPanel.showMethodDetails(details, objectMapper),
                        detailPanel::clear
                );
    }

    private void confirmAndClear() {
        int confirmation = JOptionPane.showConfirmDialog(
                this,
                "This will clear in-memory data and truncate all JSONL files under the data directory. Continue?",
                "Confirm reset",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (confirmation != JOptionPane.YES_OPTION) {
            return;
        }

        collector.resetAllData();
        previouslyKnownMethods.clear();
        refreshNow();
    }

    private void exportSelectedRows() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            JOptionPane.showMessageDialog(this, "Select one or more methods in the table first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        ArrayNode methodExports = objectMapper.createArrayNode();

        for (int selectedRow : selectedRows) {
            int modelRow = table.convertRowIndexToModel(selectedRow);
            JsonRpcIndex.MethodRow row = tableModel.rowAt(modelRow);
            index.snapshotMethodDetails(row.methodName())
                    .ifPresent(details -> methodExports.add(buildMethodExport(details)));
        }

        if (methodExports.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No exportable records were found for the selected rows.", "Nothing to export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        ObjectNode root = objectMapper.createObjectNode();
        root.put("generatedAt", Instant.now().toString());
        root.put("mode", "manual-only");
        root.put("note", "Generated templates are for manual review in Repeater. The extension never auto-sends mutations.");
        root.set("methods", methodExports);

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export JSON-RPC manual test templates");
        chooser.setSelectedFile(new File("jsonrpc-manual-tests-" + Instant.now().toEpochMilli() + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String payload = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
            Files.writeString(destination.toPath(), payload, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Export written to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting JSON-RPC templates.", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportAllData() {
        ObjectNode payload = exportService.buildFullExport();

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export all LogicHunter data");
        chooser.setSelectedFile(new File("logichunter-export-" + Instant.now().toEpochMilli() + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String text = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
            Files.writeString(destination.toPath(), text, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Export written to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting LogicHunter full dataset.", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportCurrentMethodOnly() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a method first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        JsonRpcIndex.MethodRow selectedMethod = tableModel.rowAt(modelRow);
        ObjectNode payload = exportService.buildMethodExport(selectedMethod.methodName());

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export current method dataset");
        chooser.setSelectedFile(new File("logichunter-method-" + selectedMethod.methodName().replaceAll("[^a-zA-Z0-9_.-]", "_") + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String text = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
            Files.writeString(destination.toPath(), text, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Export written to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting method dataset.", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private ObjectNode buildMethodExport(JsonRpcIndex.MethodDetails details) {
        ObjectNode methodNode = objectMapper.createObjectNode();
        methodNode.put("methodName", details.row().methodName());
        methodNode.put("count", details.row().count());
        methodNode.put("uniqueVariants", details.row().uniqueVariants());
        methodNode.put("paramKeys", details.row().paramKeys());
        methodNode.put("firstSeen", details.row().firstSeen() == null ? "" : details.row().firstSeen().toString());
        methodNode.put("lastSeen", details.row().lastSeen() == null ? "" : details.row().lastSeen().toString());

        ArrayNode samples = objectMapper.createArrayNode();
        for (JsonRpcRecord sample : details.sampleRawRecords()) {
            samples.add(buildSampleExport(sample));
        }

        methodNode.set("samples", samples);
        return methodNode;
    }

    private ObjectNode buildSampleExport(JsonRpcRecord sample) {
        ObjectNode sampleNode = objectMapper.createObjectNode();
        sampleNode.put("recordId", sample.recordId());
        sampleNode.put("timestamp", sample.timestamp().toString());

        ObjectNode requestNode = objectMapper.createObjectNode();
        requestNode.put("url", sample.request().url());
        requestNode.put("httpMethod", sample.request().httpMethod());
        ArrayNode headers = objectMapper.createArrayNode();
        for (String header : sample.request().headers()) {
            headers.add(header);
        }
        requestNode.set("headers", headers);
        requestNode.put("rawHttp", sample.request().rawHttpText());
        requestNode.put("body", sample.request().bodyText());

        ArrayNode mutationTemplates = objectMapper.createArrayNode();
        mutationTemplates.add(buildMutationTemplate("original", sample.request().bodyText()));

        try {
            JsonNode parsed = objectMapper.readTree(sample.request().bodyText());
            if (parsed.isObject()) {
                ObjectNode rootObj = (ObjectNode) parsed;

                ObjectNode withoutParams = rootObj.deepCopy();
                withoutParams.remove("params");
                mutationTemplates.add(buildMutationTemplate("params_removed", objectMapper.writeValueAsString(withoutParams)));

                ObjectNode paramsEmptyObject = rootObj.deepCopy();
                paramsEmptyObject.set("params", objectMapper.createObjectNode());
                mutationTemplates.add(buildMutationTemplate("params_empty_object", objectMapper.writeValueAsString(paramsEmptyObject)));

                ObjectNode paramsNull = rootObj.deepCopy();
                paramsNull.putNull("params");
                mutationTemplates.add(buildMutationTemplate("params_null", objectMapper.writeValueAsString(paramsNull)));

                ObjectNode harmlessField = rootObj.deepCopy();
                harmlessField.put("_collector_note", "manual-review");
                mutationTemplates.add(buildMutationTemplate("extra_harmless_field", objectMapper.writeValueAsString(harmlessField)));
            }
        } catch (Exception ignored) {
            // Mutations require object JSON; keep original only when parsing fails.
        }

        requestNode.set("manualMutations", mutationTemplates);
        sampleNode.set("request", requestNode);

        if (sample.response().present()) {
            ObjectNode responseNode = objectMapper.createObjectNode();
            responseNode.put("status", sample.response().statusCode() == null ? 0 : sample.response().statusCode());
            ArrayNode responseHeaders = objectMapper.createArrayNode();
            for (String header : sample.response().headers()) {
                responseHeaders.add(header);
            }
            responseNode.set("headers", responseHeaders);
            responseNode.put("rawHttp", sample.response().rawHttpText());
            responseNode.put("body", sample.response().bodyText());
            sampleNode.set("response", responseNode);
        } else {
            sampleNode.put("response", "missing");
        }

        return sampleNode;
    }

    private ObjectNode buildMutationTemplate(String name, String body) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("name", name);
        node.put("body", body == null ? "" : body);
        return node;
    }

    private void updateStatsLabel(JsonRpcIndex.Stats stats) {
        String text = "Total records: " + stats.totalRecords()
                + " | Distinct methods: " + stats.distinctMethods()
                + " | Empty params: " + stats.methodsWithEmptyParams()
                + " | Seen once: " + stats.methodsSeenOnce()
                + " | Multi-variant: " + stats.methodsWithMultipleVariants()
                + " | Large responses: " + stats.methodsWithLargeResponses();
        statsLabel.setText(text);
    }

    private final class MethodCellRenderer extends DefaultTableCellRenderer {
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
            JsonRpcIndex.MethodRow methodRow = tableModel.rowAt(modelRow);
            RoleType roleType = authContextStore.roleForMethod(methodRow.methodName());
            if (tableModel.isNewMethod(modelRow)) {
                component.setBackground(new Color(226, 245, 218));
            } else if (methodRow.isRare()) {
                component.setBackground(new Color(255, 240, 214));
            } else {
                component.setBackground(UIManager.getColor("Table.background"));
            }

            if (column == 1) {
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

    private enum FilterOption {
        ALL_METHODS("All methods") {
            @Override
            boolean accept(JsonRpcIndex.MethodRow row) {
                return true;
            }
        },
        EMPTY_PARAMS("Methods with empty params") {
            @Override
            boolean accept(JsonRpcIndex.MethodRow row) {
                return row.hasEmptyParams();
            }
        },
        MULTIPLE_VARIANTS("Methods with multiple variants") {
            @Override
            boolean accept(JsonRpcIndex.MethodRow row) {
                return row.uniqueVariants() > 1;
            }
        },
        LARGE_RESPONSES("Methods with large responses") {
            @Override
            boolean accept(JsonRpcIndex.MethodRow row) {
                return row.hasLargeResponses();
            }
        };

        private final String label;

        FilterOption(String label) {
            this.label = label;
        }

        abstract boolean accept(JsonRpcIndex.MethodRow row);

        @Override
        public String toString() {
            return label;
        }
    }
}
