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
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AttackSuggestionsTab extends JPanel {
    private final MontoyaApi api;
    private final AttackSuggestionService suggestionService;
    private final JsonRpcCollector collector;
    private final ObjectMapper objectMapper;

    private final AttackSuggestionTableModel tableModel = new AttackSuggestionTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<AttackSuggestionTableModel> sorter = new TableRowSorter<>(tableModel);

    private final JTextField searchField = new JTextField(30);
    private final JLabel statusLabel = new JLabel("No suggestions yet");
    private final JTextArea detailArea = buildTextArea();

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);

    public AttackSuggestionsTab(
            MontoyaApi api,
            AttackSuggestionService suggestionService,
            JsonRpcCollector collector,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.suggestionService = suggestionService;
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
        controls.add(new JLabel("Search suggestions:"));
        controls.add(searchField);

        JButton refreshButton = new JButton("Refresh");
        JButton recomputeButton = new JButton("Recompute");
        JButton exportButton = new JButton("Export Selected");

        refreshButton.addActionListener(e -> refreshNow());
        recomputeButton.addActionListener(e -> suggestionService.requestRecomputeAsync());
        exportButton.addActionListener(e -> exportSelectedSuggestion());

        controls.add(refreshButton);
        controls.add(recomputeButton);
        controls.add(exportButton);

        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(sorter);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        table.getColumnModel().getColumn(0).setPreferredWidth(360);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(210);
        table.getColumnModel().getColumn(3).setPreferredWidth(120);
        table.getColumnModel().getColumn(4).setPreferredWidth(160);
        table.getColumnModel().getColumn(5).setPreferredWidth(130);
        table.getColumnModel().getColumn(6).setPreferredWidth(170);
        table.getColumnModel().getColumn(7).setPreferredWidth(220);
        table.getColumnModel().getColumn(8).setPreferredWidth(420);
        table.getColumnModel().getColumn(9).setPreferredWidth(520);

        table.setDefaultRenderer(Object.class, new PriorityCellRenderer());

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Attack Suggestions"));

        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Suggestion Details"));

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
        List<AttackSuggestion> suggestions = suggestionService.snapshotSuggestions();
        tableModel.setRows(suggestions);
        applyFilters();

        long high = suggestions.stream()
            .filter(suggestion -> suggestion.confidence() == AttackSuggestion.Confidence.HIGH)
                .count();

        statusLabel.setText("Findings: " + suggestions.size() + " | HIGH confidence: " + high);

        if (!suggestions.isEmpty() && table.getSelectedRow() < 0) {
            table.setRowSelectionInterval(0, 0);
        }

        showSelectedDetails();
    }

    private void applyFilters() {
        String query = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);

        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends AttackSuggestionTableModel, ? extends Integer> entry) {
                AttackSuggestion row = tableModel.rowAt(entry.getIdentifier());
                if (query.isBlank()) {
                    return true;
                }

                return row.findingTitle().toLowerCase(Locale.ROOT).contains(query)
                        || row.category().toLowerCase(Locale.ROOT).contains(query)
                        || row.attackPath().toLowerCase(Locale.ROOT).contains(query)
                        || row.observation().toLowerCase(Locale.ROOT).contains(query)
                        || row.whySuspicious().toLowerCase(Locale.ROOT).contains(query)
                        || row.impact().toLowerCase(Locale.ROOT).contains(query)
                        || row.confidenceDisplay().toLowerCase(Locale.ROOT).contains(query);
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
        AttackSuggestion selected = tableModel.rowAt(modelRow);

        try {
            detailArea.setText(selected.toFormattedFinding());
        } catch (Exception ex) {
            detailArea.setText("Unable to render suggestion details: " + ex.getMessage());
        }
    }

    private void exportSelectedSuggestion() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        AttackSuggestion selected = tableModel.rowAt(modelRow);

        ObjectNode payload;
        try {
            payload = suggestionService.buildManualExportBundle(selected.suggestionId());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not build suggestion export bundle: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export attack suggestion bundle");
        chooser.setSelectedFile(new File("logichunter-suggestion-" + selected.suggestionId() + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String text = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
            Files.writeString(destination.toPath(), text, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Suggestion bundle exported to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting attack suggestion bundle.", ex);
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

    private final class PriorityCellRenderer extends DefaultTableCellRenderer {
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
            AttackSuggestion suggestion = tableModel.rowAt(modelRow);
            if (suggestion.confidence() == AttackSuggestion.Confidence.HIGH) {
                component.setBackground(new Color(255, 225, 225));
            } else if (suggestion.confidence() == AttackSuggestion.Confidence.MEDIUM) {
                component.setBackground(new Color(255, 239, 221));
            } else {
                component.setBackground(UIManager.getColor("Table.background"));
            }
            return component;
        }
    }
}
