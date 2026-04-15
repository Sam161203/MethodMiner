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
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

public final class WorkflowGraphTab extends JPanel {
    private final MontoyaApi api;
    private final WorkflowGraphService workflowGraphService;
    private final JsonRpcCollector collector;
    private final ObjectMapper objectMapper;

    private final WorkflowNodeTableModel nodeTableModel = new WorkflowNodeTableModel();
    private final WorkflowEdgeTableModel edgeTableModel = new WorkflowEdgeTableModel();
    private final WorkflowChainTableModel chainTableModel = new WorkflowChainTableModel();

    private final JTable nodeTable = new JTable(nodeTableModel);
    private final JTable edgeTable = new JTable(edgeTableModel);
    private final JTable chainTable = new JTable(chainTableModel);

    private final TableRowSorter<WorkflowNodeTableModel> nodeSorter = new TableRowSorter<>(nodeTableModel);
    private final TableRowSorter<WorkflowEdgeTableModel> edgeSorter = new TableRowSorter<>(edgeTableModel);
    private final TableRowSorter<WorkflowChainTableModel> chainSorter = new TableRowSorter<>(chainTableModel);

    private final JTextField searchField = new JTextField(30);
    private final JLabel statusLabel = new JLabel("No workflow correlations yet");
    private final JTextArea detailArea = buildTextArea();

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);

    private WorkflowGraphService.WorkflowGraphSnapshot lastSnapshot = new WorkflowGraphService.WorkflowGraphSnapshot(
            0,
            0,
            0,
            java.util.List.of(),
            java.util.List.of(),
            java.util.List.of()
    );

    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.ROOT)
            .withZone(ZoneId.systemDefault());

    public WorkflowGraphTab(
            MontoyaApi api,
            WorkflowGraphService workflowGraphService,
            JsonRpcCollector collector,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.workflowGraphService = workflowGraphService;
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
        controls.add(new JLabel("Search graph:"));
        controls.add(searchField);

        JButton refreshButton = new JButton("Refresh");
        JButton exportButton = new JButton("Export Selected Chain");

        refreshButton.addActionListener(e -> refreshNow());
        exportButton.addActionListener(e -> exportSelectedChain());

        controls.add(refreshButton);
        controls.add(exportButton);

        configureTable(nodeTable, nodeSorter);
        configureTable(edgeTable, edgeSorter);
        configureTable(chainTable, chainSorter);

        nodeTable.getColumnModel().getColumn(0).setPreferredWidth(250);
        nodeTable.getColumnModel().getColumn(6).setPreferredWidth(220);

        edgeTable.getColumnModel().getColumn(0).setPreferredWidth(210);
        edgeTable.getColumnModel().getColumn(1).setPreferredWidth(210);
        edgeTable.getColumnModel().getColumn(4).setPreferredWidth(260);

        chainTable.getColumnModel().getColumn(0).setPreferredWidth(450);
        chainTable.getColumnModel().getColumn(4).setPreferredWidth(360);

        nodeTable.setDefaultRenderer(Object.class, new NodeCellRenderer());
        edgeTable.setDefaultRenderer(Object.class, new EdgeCellRenderer());
        nodeTable.setDefaultRenderer(Instant.class, new TimeCellRenderer());
        edgeTable.setDefaultRenderer(Instant.class, new TimeCellRenderer());

        JScrollPane nodeScroll = new JScrollPane(nodeTable);
        nodeScroll.setBorder(BorderFactory.createTitledBorder("Top 20 Most Connected Methods"));

        JScrollPane edgeScroll = new JScrollPane(edgeTable);
        edgeScroll.setBorder(BorderFactory.createTitledBorder("Method-to-Method Correlation Edges"));

        JScrollPane chainScroll = new JScrollPane(chainTable);
        chainScroll.setBorder(BorderFactory.createTitledBorder("Inferred Workflow Chains"));

        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Workflow Details"));

        JSplitPane upperSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, nodeScroll, edgeScroll);
        upperSplit.setResizeWeight(0.45);

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, chainScroll, detailScroll);
        lowerSplit.setResizeWeight(0.45);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, upperSplit, lowerSplit);
        mainSplit.setResizeWeight(0.5);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        footer.add(statusLabel, BorderLayout.WEST);

        add(controls, BorderLayout.NORTH);
        add(mainSplit, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    private void configureTable(JTable table, TableRowSorter<?> sorter) {
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(sorter);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
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

        nodeTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showNodeDetails();
            }
        });

        edgeTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showEdgeDetails();
            }
        });

        chainTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showChainDetails();
            }
        });
    }

    private void refreshNow() {
        lastSnapshot = workflowGraphService.snapshot();

        nodeTableModel.setRows(lastSnapshot.topConnectedMethods());
        edgeTableModel.setRows(lastSnapshot.edges());
        chainTableModel.setRows(lastSnapshot.chains());

        applyFilters();

        statusLabel.setText(
                "Methods: " + lastSnapshot.totalMethods()
                        + " | Edges: " + lastSnapshot.totalEdges()
                        + " | Correlations: " + lastSnapshot.totalCorrelations()
        );

        if (nodeTable.getSelectedRow() < 0 && nodeTable.getRowCount() > 0) {
            nodeTable.setRowSelectionInterval(0, 0);
        }
        if (chainTable.getSelectedRow() < 0 && chainTable.getRowCount() > 0) {
            chainTable.setRowSelectionInterval(0, 0);
        }

        showChainDetails();
    }

    private void applyFilters() {
        String query = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase(Locale.ROOT);

        nodeSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends WorkflowNodeTableModel, ? extends Integer> entry) {
                WorkflowGraphService.MethodNodeView row = nodeTableModel.rowAt(entry.getIdentifier());
                if (query.isBlank()) {
                    return true;
                }
                return row.methodName().toLowerCase(Locale.ROOT).contains(query)
                        || row.entityHighlights().toLowerCase(Locale.ROOT).contains(query);
            }
        });

        edgeSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends WorkflowEdgeTableModel, ? extends Integer> entry) {
                WorkflowGraphService.EdgeView row = edgeTableModel.rowAt(entry.getIdentifier());
                if (query.isBlank()) {
                    return true;
                }
                return row.sourceMethod().toLowerCase(Locale.ROOT).contains(query)
                        || row.targetMethod().toLowerCase(Locale.ROOT).contains(query)
                        || row.entityHighlights().toLowerCase(Locale.ROOT).contains(query)
                        || row.sharedValues().toLowerCase(Locale.ROOT).contains(query);
            }
        });

        chainSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends WorkflowChainTableModel, ? extends Integer> entry) {
                WorkflowGraphService.ChainView row = chainTableModel.rowAt(entry.getIdentifier());
                if (query.isBlank()) {
                    return true;
                }
                return row.path().toLowerCase(Locale.ROOT).contains(query)
                        || row.highlights().toLowerCase(Locale.ROOT).contains(query)
                        || row.rationale().toLowerCase(Locale.ROOT).contains(query);
            }
        });
    }

    private void showNodeDetails() {
        int viewRow = nodeTable.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = nodeTable.convertRowIndexToModel(viewRow);
        WorkflowGraphService.MethodNodeView row = nodeTableModel.rowAt(modelRow);

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("type", "method-node");
            json.put("method", row.methodName());
            json.put("observations", row.observations());
            json.put("weightedConnections", row.weightedConnections());
            json.put("inDegree", row.inDegree());
            json.put("outDegree", row.outDegree());
            json.put("entryPoint", row.entryPoint());
            json.put("privilegedEndpoint", row.privilegedEndpoint());
            json.put("entityHighlights", row.entityHighlights());
            json.put("firstSeen", row.firstSeen() == null ? "" : row.firstSeen().toString());
            json.put("lastSeen", row.lastSeen() == null ? "" : row.lastSeen().toString());
            detailArea.setText(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json));
        } catch (Exception ex) {
            detailArea.setText("Unable to render node details: " + ex.getMessage());
        }
    }

    private void showEdgeDetails() {
        int viewRow = edgeTable.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = edgeTable.convertRowIndexToModel(viewRow);
        WorkflowGraphService.EdgeView row = edgeTableModel.rowAt(modelRow);

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("type", "edge");
            json.put("edgeId", row.edgeId());
            json.put("sourceMethod", row.sourceMethod());
            json.put("targetMethod", row.targetMethod());
            json.put("correlations", row.correlations());
            json.put("entityHighlights", row.entityHighlights());
            json.put("sharedValues", row.sharedValues());
            json.put("linkagePaths", row.linkagePaths());
            json.put("firstSeen", row.firstSeen() == null ? "" : row.firstSeen().toString());
            json.put("lastSeen", row.lastSeen() == null ? "" : row.lastSeen().toString());
            detailArea.setText(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json));
        } catch (Exception ex) {
            detailArea.setText("Unable to render edge details: " + ex.getMessage());
        }
    }

    private void showChainDetails() {
        int viewRow = chainTable.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = chainTable.convertRowIndexToModel(viewRow);
        WorkflowGraphService.ChainView row = chainTableModel.rowAt(modelRow);

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("type", "workflow-chain");
            json.put("chainId", row.chainId());
            json.put("path", row.path());
            json.put("steps", row.steps());
            json.put("score", row.score());
            json.put("highlights", row.highlights());
            json.put("rationale", row.rationale());
            detailArea.setText(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json));
        } catch (Exception ex) {
            detailArea.setText("Unable to render chain details: " + ex.getMessage());
        }
    }

    private void exportSelectedChain() {
        int viewRow = chainTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Select a workflow chain first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = chainTable.convertRowIndexToModel(viewRow);
        WorkflowGraphService.ChainView chain = chainTableModel.rowAt(modelRow);

        ObjectNode payload;
        try {
            payload = workflowGraphService.buildChainExportBundle(chain.chainId());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not build chain export bundle: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser(collector.storageManager().projectRoot().toFile());
        chooser.setDialogTitle("Export workflow chain bundle");
        chooser.setSelectedFile(new File("jsonrpc-workflow-chain-" + chain.chainId() + ".json"));

        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = chooser.getSelectedFile();
        try {
            String text = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
            Files.writeString(destination.toPath(), text, StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this, "Workflow chain bundle exported to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting workflow chain bundle.", ex);
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

    private final class NodeCellRenderer extends DefaultTableCellRenderer {
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
            WorkflowGraphService.MethodNodeView node = nodeTableModel.rowAt(modelRow);
            if (node.privilegedEndpoint()) {
                component.setBackground(new Color(255, 232, 232));
            } else if (node.entryPoint()) {
                component.setBackground(new Color(230, 242, 255));
            } else {
                component.setBackground(UIManager.getColor("Table.background"));
            }

            return component;
        }
    }

    private final class EdgeCellRenderer extends DefaultTableCellRenderer {
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
            WorkflowGraphService.EdgeView edge = edgeTableModel.rowAt(modelRow);

            if (!"(none)".equals(edge.entityHighlights())) {
                component.setBackground(new Color(245, 239, 220));
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
