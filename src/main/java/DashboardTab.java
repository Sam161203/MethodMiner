import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
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
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Consolidated dashboard tab: Methods + Entities + Auth Sessions.
 * Replaces the separate Methods and Entity Store tabs.
 */
public final class DashboardTab extends JPanel {
    private final MontoyaApi api;
    private final JsonRpcCollector collector;
    private final JsonRpcIndex index;
    private final AuthContextStore authContextStore;
    private final EntityStoreService entityStoreService;
    private final LogicHunterExportService exportService;
    private final ObjectMapper objectMapper;

    private final JsonRpcTableModel tableModel = new JsonRpcTableModel();
    private final JTable methodTable = new JTable(tableModel);
    private final TableRowSorter<JsonRpcTableModel> sorter = new TableRowSorter<>(tableModel);

    private final JTextField searchField = new JTextField(30);
    private final JComboBox<FilterOption> filterComboBox = new JComboBox<>(FilterOption.values());
    private final JLabel statsLabel = new JLabel("No records yet");

    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JsonRpcDetailPanel trafficPanel = new JsonRpcDetailPanel();
    private final JTextArea entitiesArea = buildMonoTextArea();
    private final SessionTableModel sessionsTableModel = new SessionTableModel();
    private final JTable sessionsTable = new JTable(sessionsTableModel);

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);
    private final Set<String> previouslyKnownMethods = new HashSet<>();

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.ROOT)
            .withZone(ZoneId.systemDefault());

    public DashboardTab(
            MontoyaApi api,
            JsonRpcCollector collector,
            JsonRpcIndex index,
            AuthContextStore authContextStore,
            EntityStoreService entityStoreService,
            LogicHunterExportService exportService,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.collector = collector;
        this.index = index;
        this.authContextStore = authContextStore;
        this.entityStoreService = entityStoreService;
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

        // Control bar
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        controls.add(new JLabel("Search:"));
        controls.add(searchField);
        controls.add(new JLabel("Filter:"));
        controls.add(filterComboBox);

        JButton refreshBtn = new JButton("Refresh");
        JButton markAdminBtn = new JButton("\u2605 Mark ADMIN");
        JButton markLowPrivBtn = new JButton("\u2606 Mark LOW_PRIV");
        JButton clearRoleBtn = new JButton("Clear Role");
        JButton exportAllBtn = new JButton("Export All");
        JButton clearBtn = new JButton("Clear / Reset");

        refreshBtn.addActionListener(e -> refreshNow());
        markAdminBtn.addActionListener(e -> applyRoleToSelectedMethod(RoleType.ADMIN));
        markLowPrivBtn.addActionListener(e -> applyRoleToSelectedMethod(RoleType.LOW_PRIV));
        clearRoleBtn.addActionListener(e -> applyRoleToSelectedMethod(RoleType.UNKNOWN));
        exportAllBtn.addActionListener(e -> exportAllData());
        clearBtn.addActionListener(e -> confirmAndClear());

        controls.add(refreshBtn);
        controls.add(markAdminBtn);
        controls.add(markLowPrivBtn);
        controls.add(clearRoleBtn);
        controls.add(exportAllBtn);
        controls.add(clearBtn);

        // Method table
        methodTable.setFillsViewportHeight(true);
        methodTable.setAutoCreateRowSorter(false);
        methodTable.setRowSorter(sorter);
        methodTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        methodTable.getColumnModel().getColumn(0).setPreferredWidth(280);
        methodTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        if (methodTable.getColumnModel().getColumnCount() > 3) {
            methodTable.getColumnModel().getColumn(3).setPreferredWidth(280);
        }
        methodTable.setDefaultRenderer(Object.class, new MethodCellRenderer());
        methodTable.setDefaultRenderer(Instant.class, new TimeCellRenderer());

        JScrollPane tableScroll = new JScrollPane(methodTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Discovered JSON-RPC Methods"));

        // Detail sub-tabs
        detailTabs.addTab("\uD83D\uDCE1 Traffic", new JScrollPane(trafficPanel));
        detailTabs.addTab("\uD83D\uDD11 Entities", new JScrollPane(entitiesArea));
        detailTabs.addTab("\uD83D\uDC64 Sessions", buildSessionsPanel());
        detailTabs.setSelectedIndex(0);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        splitPane.setResizeWeight(0.45);

        // Footer
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        footer.add(statsLabel, BorderLayout.WEST);

        add(controls, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    private JPanel buildSessionsPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        sessionsTable.setFillsViewportHeight(true);
        sessionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sessionsTable.getColumnModel().getColumn(0).setPreferredWidth(420);
        sessionsTable.getColumnModel().getColumn(1).setPreferredWidth(170);
        sessionsTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        sessionsTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        sessionsTable.getColumnModel().getColumn(4).setPreferredWidth(110);
        sessionsTable.getColumnModel().getColumn(5).setPreferredWidth(90);
        sessionsTable.getColumnModel().getColumn(6).setPreferredWidth(170);
        sessionsTable.getColumnModel().getColumn(7).setPreferredWidth(260);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton markAdminBtn = new JButton("Mark ADMIN");
        JButton markLowPrivBtn = new JButton("Mark LOW_PRIV");
        JButton clearRoleBtn = new JButton("Clear Role");
        JButton refreshBtn = new JButton("Refresh Sessions");

        markAdminBtn.addActionListener(e -> applyRoleToSelectedSession(RoleType.ADMIN));
        markLowPrivBtn.addActionListener(e -> applyRoleToSelectedSession(RoleType.LOW_PRIV));
        clearRoleBtn.addActionListener(e -> applyRoleToSelectedSession(RoleType.UNKNOWN));
        refreshBtn.addActionListener(e -> refreshSessionsPanel());

        controls.add(markAdminBtn);
        controls.add(markLowPrivBtn);
        controls.add(clearRoleBtn);
        controls.add(refreshBtn);

        panel.add(controls, BorderLayout.NORTH);
        panel.add(new JScrollPane(sessionsTable), BorderLayout.CENTER);
        return panel;
    }

    private void wireEvents() {
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilters(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilters(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });

        filterComboBox.addActionListener(e -> applyFilters());

        methodTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedDetails();
            }
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
        refreshSessionsPanel();
    }

    private void showSelectedDetails() {
        int viewRow = methodTable.getSelectedRow();
        if (viewRow < 0) {
            trafficPanel.clear();
            entitiesArea.setText("");
            return;
        }

        int modelRow = methodTable.convertRowIndexToModel(viewRow);
        JsonRpcIndex.MethodRow selected = tableModel.rowAt(modelRow);

        // Traffic sub-tab
        index.snapshotMethodDetails(selected.methodName())
                .ifPresentOrElse(
                        details -> trafficPanel.showMethodDetails(details, objectMapper),
                        trafficPanel::clear
                );

        // Entities sub-tab
        refreshEntitiesPanel(selected.methodName());
    }

    private void refreshEntitiesPanel(String methodName) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Entities for method: ").append(methodName).append(" ===\n\n");

        List<EntityStoreService.EntityRow> allEntities = entityStoreService.snapshotRows();
        int count = 0;

        for (EntityStoreService.EntityRow entity : allEntities) {
            Optional<EntityStoreService.EntityDetails> details = entityStoreService.snapshotEntityDetails(entity.entityKey());
            if (details.isEmpty()) {
                continue;
            }
            if (!details.get().methods().contains(methodName)) {
                continue;
            }

            count++;
            sb.append(entity.entityType().displayName()).append(": ").append(entity.preview()).append("\n");
            sb.append("  Risk: ").append(entity.riskDisplay()).append("\n");
            sb.append("  Cross-method: ").append(entity.crossMethodReuse() ? "\u2713 YES" : "\u2717 No").append("\n");
            sb.append("  Cross-context: ").append(entity.crossContextReuse() ? "\u2713 YES" : "\u2717 No").append("\n");

            List<String> methods = details.get().methods();
            if (methods.size() > 1) {
                sb.append("  Also seen in: ");
                int shown = 0;
                for (String m : methods) {
                    if (!m.equals(methodName)) {
                        if (shown > 0) sb.append(", ");
                        sb.append(m);
                        shown++;
                        if (shown >= 6) {
                            sb.append(" ... +").append(methods.size() - shown - 1).append(" more");
                            break;
                        }
                    }
                }
                sb.append("\n");
            }
            sb.append("\n");
        }

        if (count == 0) {
            sb.append("No entities found for this method yet.\n");
            sb.append("Entities are extracted from request/response parameters (IDs, tokens, tenant/user references).\n");
        } else {
            sb.append("Total: ").append(count).append(" entities\n");
        }

        entitiesArea.setText(sb.toString());
        entitiesArea.setCaretPosition(0);
    }

    private void refreshSessionsPanel() {
        sessionsTableModel.setRows(authContextStore.snapshotSessions());
    }

    private void applyRoleToSelectedSession(RoleType roleType) {
        int viewRow = sessionsTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a session first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = sessionsTable.convertRowIndexToModel(viewRow);
        AuthContextStore.SessionView session = sessionsTableModel.rowAt(modelRow);
        boolean updated = authContextStore.setRoleForContextKey(session.contextKey(), roleType);
        if (!updated) {
            JOptionPane.showMessageDialog(this, "Unable to update role for selected session.", "Role update failed", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        refreshNow();
    }

    private void applyRoleToSelectedMethod(RoleType roleType) {
        int viewRow = methodTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a method first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = methodTable.convertRowIndexToModel(viewRow);
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
                if (option != null && !option.accept(row)) {
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

    private void updateStatsLabel(JsonRpcIndex.Stats stats) {
        AuthContextStore.AuthContext adminCtx = authContextStore.firstContextByRole(RoleType.ADMIN);
        AuthContextStore.AuthContext lowPrivCtx = authContextStore.firstContextByRole(RoleType.LOW_PRIV);

        String roleStatus = "";
        if (adminCtx != null && lowPrivCtx != null) {
            roleStatus = " | \u2705 ADMIN + LOW_PRIV sessions configured";
        } else if (adminCtx != null) {
            roleStatus = " | \u26A0 ADMIN configured, need LOW_PRIV";
        } else if (lowPrivCtx != null) {
            roleStatus = " | \u26A0 LOW_PRIV configured, need ADMIN";
        } else {
            roleStatus = " | \u274C No roles configured — mark sessions above";
        }

        String text = "Records: " + stats.totalRecords()
                + " | Methods: " + stats.distinctMethods()
                + " | Multi-variant: " + stats.methodsWithMultipleVariants()
                + roleStatus;
        statsLabel.setText(text);
    }

    private static JTextArea buildMonoTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private final class SessionTableModel extends AbstractTableModel {
        private final String[] columns = {
                "Context Key",
                "Session ID",
                "Database",
                "User",
                "Role",
                "Requests",
                "Last Seen",
                "Security Groups"
        };

        private final List<AuthContextStore.SessionView> rows = new java.util.ArrayList<>();

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            AuthContextStore.SessionView row = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> row.contextKey();
                case 1 -> row.sessionId();
                case 2 -> row.database();
                case 3 -> row.userName();
                case 4 -> row.role().displayName();
                case 5 -> row.requestCount();
                case 6 -> row.lastSeen() == null ? "" : timeFormatter.format(row.lastSeen());
                case 7 -> String.join(", ", row.securityGroups());
                default -> "";
            };
        }

        void setRows(List<AuthContextStore.SessionView> nextRows) {
            rows.clear();
            rows.addAll(nextRows);
            fireTableDataChanged();
        }

        AuthContextStore.SessionView rowAt(int rowIndex) {
            return rows.get(rowIndex);
        }
    }

    private final class MethodCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
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
                    case MIXED -> component.setForeground(new Color(0, 102, 153));
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
            @Override boolean accept(JsonRpcIndex.MethodRow row) { return true; }
        },
        EMPTY_PARAMS("Methods with empty params") {
            @Override boolean accept(JsonRpcIndex.MethodRow row) { return row.hasEmptyParams(); }
        },
        MULTIPLE_VARIANTS("Methods with multiple variants") {
            @Override boolean accept(JsonRpcIndex.MethodRow row) { return row.uniqueVariants() > 1; }
        },
        LARGE_RESPONSES("Methods with large responses") {
            @Override boolean accept(JsonRpcIndex.MethodRow row) { return row.hasLargeResponses(); }
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
