import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
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
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public final class EntityStoreTab extends JPanel {
    private final MontoyaApi api;
    private final EntityStoreService entityStoreService;
    private final JsonRpcCollector collector;
    private final ObjectMapper objectMapper;

    private final EntityRowTableModel tableModel = new EntityRowTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<EntityRowTableModel> sorter = new TableRowSorter<>(tableModel);

    private final JTextField searchField = new JTextField(30);
    private final JLabel statusLabel = new JLabel("No entities observed yet");
    private final JTextArea detailArea = buildTextArea();

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.ROOT)
            .withZone(ZoneId.systemDefault());

    public EntityStoreTab(
            MontoyaApi api,
            EntityStoreService entityStoreService,
            JsonRpcCollector collector,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.entityStoreService = entityStoreService;
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
        controls.add(new JLabel("Search entities:"));
        controls.add(searchField);

        JButton refreshButton = new JButton("Refresh");
        JButton exportButton = new JButton("Export Entity Bundle");

        refreshButton.addActionListener(e -> refreshNow());
        exportButton.addActionListener(e -> exportSelectedEntity());

        controls.add(refreshButton);
        controls.add(exportButton);

        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(sorter);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        table.getColumnModel().getColumn(0).setPreferredWidth(280);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(110);
        table.getColumnModel().getColumn(3).setPreferredWidth(100);
        table.getColumnModel().getColumn(4).setPreferredWidth(80);
        table.getColumnModel().getColumn(5).setPreferredWidth(80);
        table.getColumnModel().getColumn(6).setPreferredWidth(100);
        table.getColumnModel().getColumn(7).setPreferredWidth(100);
        table.getColumnModel().getColumn(8).setPreferredWidth(140);
        table.getColumnModel().getColumn(9).setPreferredWidth(140);

        table.setDefaultRenderer(Object.class, new EntityCellRenderer());
        table.setDefaultRenderer(Instant.class, new TimeCellRenderer());

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Entity Store"));

        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Entity Details"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        splitPane.setResizeWeight(0.5);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        footer.add(statusLabel, BorderLayout.WEST);

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

        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedDetails();
            }
        });
    }

    private void refreshNow() {
        List<EntityStoreService.EntityRow> rows = entityStoreService.snapshotRows();
        tableModel.setRows(rows);
        applyFilters();

        EntityStoreService.EntityStats stats = entityStoreService.snapshotStats();
        statusLabel.setText(
                "Entities: " + stats.totalEntities()
                        + " | Cross-method: " + stats.crossMethodEntities()
                        + " | Cross-context: " + stats.crossContextEntities()
        );

        if (!rows.isEmpty() && table.getSelectedRow() < 0) {
            table.setRowSelectionInterval(0, 0);
        }

        showSelectedDetails();
    }

    private void applyFilters() {
        String query = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);

        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends EntityRowTableModel, ? extends Integer> entry) {
                EntityStoreService.EntityRow row = tableModel.rowAt(entry.getIdentifier());
                if (query.isBlank()) {
                    return true;
                }

                return row.preview().toLowerCase(Locale.ROOT).contains(query)
                        || row.entityKey().toLowerCase(Locale.ROOT).contains(query)
                        || row.entityType().displayName().toLowerCase(Locale.ROOT).contains(query);
            }
        });
    }

    private void showSelectedDetails() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailArea.setText("");
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        EntityStoreService.EntityRow selected = tableModel.rowAt(modelRow);

        Optional<EntityStoreService.EntityDetails> details = entityStoreService.snapshotEntityDetails(selected.entityKey());
        if (details.isEmpty()) {
            detailArea.setText("No details available for selected entity.");
            return;
        }

        try {
            ObjectNode json = details.get().toJson(objectMapper);
            detailArea.setText(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json));
        } catch (Exception ex) {
            detailArea.setText("Unable to render entity details: " + ex.getMessage());
        }
    }

    private void exportSelectedEntity() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select an entity first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        EntityStoreService.EntityRow selected = tableModel.rowAt(modelRow);

        ObjectNode payload;
        try {
            payload = entityStoreService.buildManualExportBundle(selected.entityKey());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not build entity export bundle: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export entity review bundle");
        chooser.setSelectedFile(new File("logichunter-entity-" + sanitizeFileName(selected.preview()) + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String text = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
            Files.writeString(destination.toPath(), text, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Entity bundle exported to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting entity bundle.", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String sanitizeFileName(String value) {
        if (value == null || value.isBlank()) {
            return "entity";
        }
        String sanitized = value.replaceAll("[^a-zA-Z0-9_.-]", "_");
        return sanitized.length() <= 64 ? sanitized : sanitized.substring(0, 64);
    }

    private static JTextArea buildTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    private final class EntityCellRenderer extends DefaultTableCellRenderer {
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
            EntityStoreService.EntityRow entity = tableModel.rowAt(modelRow);

            if (entity.riskLevel() == SecurityFinding.RiskLevel.CRITICAL) {
                component.setBackground(new Color(255, 226, 226));
            } else if (entity.riskLevel() == SecurityFinding.RiskLevel.HIGH) {
                component.setBackground(new Color(255, 240, 221));
            } else if (entity.crossContextReuse()) {
                component.setBackground(new Color(255, 248, 226));
            } else {
                component.setBackground(UIManager.getColor("Table.background"));
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
}
