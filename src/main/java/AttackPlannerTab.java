import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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
import javax.swing.JTextPane;
import javax.swing.ListSelectionModel;
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
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Consolidated attack planner tab: Suggestions + Payload Copy + Evidence + Workflow.
 * Replaces the separate Findings, Attack Suggestions, and Workflow Graph tabs.
 */
public final class AttackPlannerTab extends JPanel {
    private final MontoyaApi api;
    private final AttackSuggestionService suggestionService;
    private final SecurityAnalyzerService securityAnalyzer;
    private final WorkflowGraphService workflowGraphService;
    private final AuthContextStore authContextStore;
    private final JsonRpcCollector collector;
    private final JsonRpcIndex index;
    private final ObjectMapper objectMapper;

    private final AttackSuggestionTableModel tableModel = new AttackSuggestionTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<AttackSuggestionTableModel> sorter = new TableRowSorter<>(tableModel);

    private final JTextField searchField = new JTextField(30);
    private final JLabel statusLabel = new JLabel("No suggestions yet");
    private final JCheckBox safeModeToggle = new JCheckBox("Safe Mode", true);

    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JTextArea payloadArea = buildMonoTextArea();
    private final JTextArea evidenceSummaryArea = buildMonoTextArea();
    private final JTextArea adminResponseArea = buildMonoTextArea();
    private final JTextArea lowPrivResponseArea = buildMonoTextArea();
    private final JTextPane diffPane = new JTextPane();
    private final JTextArea chainsArea = buildMonoTextArea();

    private final AtomicBoolean refreshQueued = new AtomicBoolean(false);

    public AttackPlannerTab(
            MontoyaApi api,
            AttackSuggestionService suggestionService,
            SecurityAnalyzerService securityAnalyzer,
            WorkflowGraphService workflowGraphService,
            AuthContextStore authContextStore,
            JsonRpcCollector collector,
            JsonRpcIndex index,
            ObjectMapper objectMapper
    ) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.suggestionService = suggestionService;
        this.securityAnalyzer = securityAnalyzer;
        this.workflowGraphService = workflowGraphService;
        this.authContextStore = authContextStore;
        this.collector = collector;
        this.index = index;
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

        JButton refreshBtn = new JButton("Refresh");
        JButton recomputeBtn = new JButton("Recompute");
        JButton copyPayloadBtn = new JButton("\uD83D\uDCCB Copy Payload");
        JButton copyCurlBtn = new JButton("\uD83D\uDCCB Copy cURL");
        JButton copyHeadersBtn = new JButton("\uD83D\uDCCB Copy Credentials");
        JButton sendRepeaterBtn = new JButton("\uD83D\uDD04 Send to Repeater");
        JButton executeSelectedBtn = new JButton("Run Active Check");
        JButton executeTopBtn = new JButton("Validate Top 5");
        JButton exportBtn = new JButton("Export Selected");

        refreshBtn.addActionListener(e -> refreshNow());
        recomputeBtn.addActionListener(e -> suggestionService.requestRecomputeAsync());
        copyPayloadBtn.addActionListener(e -> copyPayloadToClipboard());
        copyCurlBtn.addActionListener(e -> copyCurlToClipboard());
        copyHeadersBtn.addActionListener(e -> copyHeadersToClipboard());
        sendRepeaterBtn.addActionListener(e -> sendToRepeater());
        executeSelectedBtn.addActionListener(e -> executeSelectedValidation());
        executeTopBtn.addActionListener(e -> executeTopValidations());
        exportBtn.addActionListener(e -> exportSelectedSuggestion());

        safeModeToggle.setSelected(suggestionService.isAttackSafeMode());
        safeModeToggle.setEnabled(suggestionService.hasAttackExecutionService());
        safeModeToggle.addActionListener(e -> suggestionService.setAttackSafeMode(safeModeToggle.isSelected()));

        controls.add(refreshBtn);
        controls.add(recomputeBtn);
        controls.add(copyPayloadBtn);
        controls.add(copyCurlBtn);
        controls.add(copyHeadersBtn);
        controls.add(sendRepeaterBtn);
        controls.add(executeSelectedBtn);
        controls.add(executeTopBtn);
        controls.add(safeModeToggle);
        controls.add(exportBtn);

        // Suggestion table
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

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
        tableScroll.setBorder(BorderFactory.createTitledBorder("Attack Suggestions (sorted by priority)"));

        // Detail sub-tabs
        detailTabs.addTab("\uD83D\uDCCB Payload", buildPayloadPanel());
        detailTabs.addTab("\uD83D\uDD0D Evidence", buildEvidencePanel());
        detailTabs.addTab("\uD83D\uDD17 Chains", new JScrollPane(chainsArea));
        detailTabs.setSelectedIndex(0);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        splitPane.setResizeWeight(0.45);

        // Footer
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));
        footer.add(statusLabel, BorderLayout.WEST);

        add(controls, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    private JPanel buildPayloadPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        JPanel payloadControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton copyAllBtn = new JButton("\uD83D\uDCCB Copy Full Payload");
        JButton copyCurlOnly = new JButton("\uD83D\uDCCB Copy cURL Only");
        JButton copyHttpBtn = new JButton("\uD83D\uDCCB Copy Raw HTTP");

        copyAllBtn.addActionListener(e -> {
            String text = payloadArea.getText();
            if (!text.isBlank()) copyToClipboard(text);
        });
        copyCurlOnly.addActionListener(e -> copyCurlToClipboard());
        copyHttpBtn.addActionListener(e -> copyHttpRequestToClipboard());

        payloadControls.add(copyAllBtn);
        payloadControls.add(copyCurlOnly);
        payloadControls.add(copyHttpBtn);
        payloadControls.add(new JLabel("  \u2191 Payloads use body credentials only (no Authorization/Cookie headers)"));

        panel.add(payloadControls, BorderLayout.NORTH);
        panel.add(new JScrollPane(payloadArea), BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildEvidencePanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));

        evidenceSummaryArea.setBorder(BorderFactory.createTitledBorder("Finding Summary"));

        adminResponseArea.setBorder(BorderFactory.createTitledBorder("ADMIN Response"));
        lowPrivResponseArea.setBorder(BorderFactory.createTitledBorder("LOW_PRIV Response"));

        JSplitPane responseSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(adminResponseArea),
                new JScrollPane(lowPrivResponseArea)
        );
        responseSplit.setResizeWeight(0.5);

        diffPane.setEditable(false);
        diffPane.setContentType("text/html");
        diffPane.setText("<html><body style='font-family:Consolas,monospace;'>Select a finding to view diff.</body></html>");
        JScrollPane diffScroll = new JScrollPane(diffPane);
        diffScroll.setBorder(BorderFactory.createTitledBorder("Diff Highlight"));

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, responseSplit, diffScroll);
        lowerSplit.setResizeWeight(0.62);

        JSplitPane outerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(evidenceSummaryArea), lowerSplit);
        outerSplit.setResizeWeight(0.38);

        panel.add(outerSplit, BorderLayout.CENTER);
        return panel;
    }

    private void wireEvents() {
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilters(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilters(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilters(); }
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
                .filter(s -> s.confidence() == AttackSuggestion.Confidence.HIGH)
                .count();
        long vulns = suggestions.stream()
                .filter(s -> s.verdict() == AttackSuggestion.Verdict.LIKELY_VULNERABILITY)
                .count();

        statusLabel.setText("Findings: " + suggestions.size()
                + " | HIGH confidence: " + high
                + " | LIKELY VULNERABLE: " + vulns);

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
                        || row.primaryMethod().toLowerCase(Locale.ROOT).contains(query)
                        || row.impact().toLowerCase(Locale.ROOT).contains(query)
                        || row.confidenceDisplay().toLowerCase(Locale.ROOT).contains(query);
            }
        });
    }

    private void showSelectedDetails() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            payloadArea.setText("");
            evidenceSummaryArea.setText("");
            adminResponseArea.setText("");
            lowPrivResponseArea.setText("");
            diffPane.setText("<html><body style='font-family:Consolas,monospace;'>Select a finding to view diff.</body></html>");
            chainsArea.setText("");
            return;
        }

        // Payload tab
        payloadArea.setText(selected.effectivePayload());
        payloadArea.setCaretPosition(0);

        // Evidence tab (summary + side-by-side responses + highlighted diff)
        evidenceSummaryArea.setText(buildEvidenceSummaryText(selected));
        evidenceSummaryArea.setCaretPosition(0);

        adminResponseArea.setText(truncateForDisplay(selected.adminResponse(), 16_000));
        adminResponseArea.setCaretPosition(0);

        lowPrivResponseArea.setText(truncateForDisplay(selected.lowPrivResponse(), 16_000));
        lowPrivResponseArea.setCaretPosition(0);

        diffPane.setText(buildDiffHtml(selected.adminResponse(), selected.lowPrivResponse()));
        diffPane.setCaretPosition(0);

        // Chains tab
        chainsArea.setText(buildChainsText(selected));
        chainsArea.setCaretPosition(0);
    }

    private String buildEvidenceSummaryText(AttackSuggestion suggestion) {
        StringBuilder sb = new StringBuilder();

        sb.append("=== ").append(suggestion.findingTitle()).append(" ===\n\n");

        sb.append("Category: ").append(suggestion.category()).append("\n");
        sb.append("Host: ").append(suggestion.host()).append("\n");
        sb.append("Priority: ").append(suggestion.priorityDisplay()).append("\n");
        sb.append("Confidence: ").append(suggestion.confidenceDisplay())
            .append(" (").append(suggestion.confidenceScore()).append("/100)").append("\n");
        sb.append("Effectiveness: ").append(suggestion.effectivenessScore()).append("/100\n");
        sb.append("Verdict: ").append(suggestion.verdictDisplay()).append("\n");
        sb.append("Primary Method: ").append(suggestion.primaryMethod()).append("\n");
        sb.append("Attack Path: ").append(suggestion.attackPath()).append("\n\n");

        sb.append("--- OBSERVATION ---\n");
        sb.append(suggestion.observation()).append("\n\n");

        sb.append("--- WHY SUSPICIOUS ---\n");
        sb.append(suggestion.whySuspicious()).append("\n\n");

        sb.append("--- EXPECTED RESULT (secure behavior) ---\n");
        sb.append(suggestion.expectedResult()).append("\n\n");

        sb.append("--- IF VULNERABLE ---\n");
        sb.append(suggestion.ifVulnerable()).append("\n\n");

        sb.append("--- IMPACT ---\n");
        sb.append(suggestion.impact()).append("\n\n");

        sb.append("--- EVIDENCE ---\n");
        sb.append(suggestion.evidence()).append("\n\n");

        sb.append("--- RESPONSE DIFF SUMMARY ---\n");
        sb.append(TextDiffUtil.summarizeDifferences(
            suggestion.adminResponse(),
            suggestion.lowPrivResponse(),
            "ADMIN vs LOW_PRIV"
        )).append("\n");

        Optional<SecurityAnalyzerService.MethodSecurityDetails> methodDetails =
            securityAnalyzer.snapshotMethodDetails(suggestion.primaryMethod());
        methodDetails.ifPresent(details -> {
            sb.append("\n--- METHOD SECURITY SUMMARY ---\n");
            sb.append("Risk: ")
                .append(details.methodRisk().level().displayName())
                .append(" (")
                .append(details.methodRisk().score())
                .append(")\n");
            sb.append("Auth context differs: ")
                .append(details.authContextBehaviorDiffers() ? "yes" : "no")
                .append("\n");
            if (details.authContextSummary() != null && !details.authContextSummary().isBlank()) {
            sb.append("Auth summary: ").append(details.authContextSummary()).append("\n");
            }
        });

        suggestionService.snapshotExecutionFinding(suggestion.suggestionId()).ifPresent(execution -> {
            sb.append("\n--- ACTIVE VALIDATION ---\n");
            sb.append("Confirmed: ").append(execution.confirmed()).append("\n");
            sb.append("Severity: ").append(execution.severity().displayName()).append("\n");
            sb.append("Category: ").append(execution.category()).append("\n");
            sb.append("Response classification: ").append(execution.responseClassification()).append("\n");
            sb.append("Summary: ").append(execution.summary()).append("\n");
            sb.append("Exploit chain: ").append(execution.exploitChain()).append("\n");
            sb.append("Executed at: ").append(execution.executedAt()).append("\n");
        });

        return sb.toString();
    }

    private static String buildDiffHtml(String adminResponse, String lowPrivResponse) {
        String admin = adminResponse == null ? "" : adminResponse;
        String low = lowPrivResponse == null ? "" : lowPrivResponse;

        String[] adminLines = admin.split("\\R", -1);
        String[] lowLines = low.split("\\R", -1);
        int max = Math.max(adminLines.length, lowLines.length);

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family:Consolas,monospace;font-size:12px;'>");
        html.append("<b>ADMIN vs LOW_PRIV</b><br/>");
        html.append("<table style='border-collapse:collapse;width:100%;' border='1' cellspacing='0' cellpadding='4'>");
        html.append("<tr style='background:#f2f2f2;'><th align='left' style='width:70px;'>Line</th><th align='left'>ADMIN</th><th align='left'>LOW_PRIV</th></tr>");

        for (int i = 0; i < max; i++) {
            String left = i < adminLines.length ? adminLines[i] : "";
            String right = i < lowLines.length ? lowLines[i] : "";
            boolean changed = !Objects.equals(left, right);

            String rowStyle = changed ? " style='background:#fffbe6;'" : "";
            String leftStyle = changed ? " style='background:#ffeaea;'" : "";
            String rightStyle = changed ? " style='background:#eaffea;'" : "";

            html.append("<tr").append(rowStyle).append(">");
            html.append("<td>").append(i + 1).append("</td>");
            html.append("<td").append(leftStyle).append("><pre style='margin:0;white-space:pre-wrap;'>")
                    .append(escapeHtml(left))
                    .append("</pre></td>");
            html.append("<td").append(rightStyle).append("><pre style='margin:0;white-space:pre-wrap;'>")
                    .append(escapeHtml(right))
                    .append("</pre></td>");
            html.append("</tr>");
        }

        html.append("</table><br/>");
        html.append("<pre style='white-space:pre-wrap;'>")
                .append(escapeHtml(TextDiffUtil.summarizeDifferences(admin, low, "ADMIN vs LOW_PRIV")))
                .append("</pre>");
        html.append("</body></html>");
        return html.toString();
    }

    private String buildChainsText(AttackSuggestion suggestion) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Workflow Chains Related to: ").append(suggestion.primaryMethod()).append(" ===\n\n");

        WorkflowGraphService.WorkflowGraphSnapshot workflow = workflowGraphService.snapshot();

        // Show edges involving this method
        int edgeCount = 0;
        for (WorkflowGraphService.EdgeView edge : workflow.edges()) {
            if (edge.sourceMethod().equals(suggestion.primaryMethod())
                    || edge.targetMethod().equals(suggestion.primaryMethod())
                    || suggestion.attackPath().contains(edge.sourceMethod())
                    || suggestion.attackPath().contains(edge.targetMethod())) {
                sb.append("EDGE: ").append(edge.sourceMethod()).append(" -> ").append(edge.targetMethod());
                sb.append(" [").append(edge.sharedValues()).append("]\n");
                edgeCount++;
            }
        }
        if (edgeCount > 0) sb.append("\n");

        // Show chains involving this method
        int chainCount = 0;
        for (WorkflowGraphService.ChainView chain : workflow.chains()) {
            if (chain.methodSequence() == null) continue;
            boolean relevant = chain.methodSequence().contains(suggestion.primaryMethod())
                    || chain.path().contains(suggestion.primaryMethod());
            if (!relevant) continue;

            sb.append("CHAIN: ").append(chain.path()).append("\n");
            sb.append("  Steps: ").append(chain.steps()).append("\n");
            sb.append("  Score: ").append(chain.score()).append("\n");
            sb.append("  Highlights: ").append(chain.highlights()).append("\n");
            sb.append("  Rationale: ").append(chain.rationale()).append("\n\n");
            chainCount++;
        }

        if (edgeCount == 0 && chainCount == 0) {
            sb.append("No workflow chains found for this method.\n");
            sb.append("Chains are built from response → request value correlations observed in traffic.\n");
        }

        return sb.toString();
    }

    private void copyPayloadToClipboard() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String payload = selected.effectivePayload();
        copyToClipboard(payload);
        JOptionPane.showMessageDialog(this, "Full payload copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    private void copyCurlToClipboard() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String curl = CopyablePayloadBuilder.buildCurlForSuggestion(selected, authContextStore, index);
        copyToClipboard(curl);
        JOptionPane.showMessageDialog(this, "cURL command copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    private void copyHeadersToClipboard() {
        StringBuilder sb = new StringBuilder();
        AuthContextStore.AuthContext lowPriv = authContextStore.firstContextByRole(RoleType.LOW_PRIV);
        AuthContextStore.AuthContext admin = authContextStore.firstContextByRole(RoleType.ADMIN);

        if (lowPriv != null) {
            sb.append("=== LOW_PRIV credentials ===\n");
            sb.append("{\"database\":\"").append(lowPriv.database()).append("\",\"sessionId\":\"")
                    .append(lowPriv.sessionId()).append("\",\"userName\":\"").append(lowPriv.userName()).append("\"}\n");
            sb.append("\n");
        }
        if (admin != null) {
            sb.append("=== ADMIN credentials ===\n");
            sb.append("{\"database\":\"").append(admin.database()).append("\",\"sessionId\":\"")
                    .append(admin.sessionId()).append("\",\"userName\":\"").append(admin.userName()).append("\"}\n");
        }

        if (sb.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No sessions captured yet. Browse the target and mark roles in the Dashboard tab.", "No credentials", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        copyToClipboard(sb.toString());
        JOptionPane.showMessageDialog(this, "Credentials copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    private void copyHttpRequestToClipboard() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String httpReq = CopyablePayloadBuilder.buildHttpRequest(selected, authContextStore, index);
        copyToClipboard(httpReq);
        JOptionPane.showMessageDialog(this, "Raw HTTP request copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    private void executeSelectedValidation() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!suggestionService.hasAttackExecutionService()) {
            JOptionPane.showMessageDialog(this, "Attack execution service is unavailable.", "Unavailable", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        safeModeToggle.setEnabled(false);
        try {
            Optional<AttackExecutionFinding> result = suggestionService.executeSuggestionValidation(selected.suggestionId());
            refreshNow();

            if (result.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No execution result returned.", "Active Validation", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            AttackExecutionFinding finding = result.get();
            JOptionPane.showMessageDialog(
                    this,
                    "Validation complete.\n\n"
                            + "Confirmed: " + finding.confirmed() + "\n"
                            + "Severity: " + finding.severity().displayName() + "\n"
                            + "Category: " + finding.category() + "\n"
                            + "Response: " + finding.responseClassification(),
                    "Active Validation",
                    JOptionPane.INFORMATION_MESSAGE
            );
        } finally {
            safeModeToggle.setEnabled(suggestionService.hasAttackExecutionService());
        }
    }

    private void executeTopValidations() {
        if (!suggestionService.hasAttackExecutionService()) {
            JOptionPane.showMessageDialog(this, "Attack execution service is unavailable.", "Unavailable", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        safeModeToggle.setEnabled(false);
        try {
            List<AttackExecutionFinding> findings = suggestionService.executeTopSuggestionValidations(5);
            refreshNow();

            long confirmed = findings.stream().filter(AttackExecutionFinding::confirmed).count();
            JOptionPane.showMessageDialog(
                    this,
                    "Validated suggestions: " + findings.size() + "\n"
                            + "Confirmed findings: " + confirmed + "\n"
                            + "Safe Mode: " + (suggestionService.isAttackSafeMode() ? "ON" : "OFF"),
                    "Batch Validation",
                    JOptionPane.INFORMATION_MESSAGE
            );
        } finally {
            safeModeToggle.setEnabled(suggestionService.hasAttackExecutionService());
        }
    }

    private void sendToRepeater() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        try {
            String rawHttp = selected.repeaterRequest();
            if (rawHttp == null || rawHttp.isBlank()) {
                rawHttp = CopyablePayloadBuilder.buildHttpRequest(selected, authContextStore, index);
            }

            String normalizedRaw = rawHttp.contains("\\r\\n") && !rawHttp.contains("\r\n")
                    ? rawHttp.replace("\\r\\n", "\r\n")
                    : rawHttp;

            String host = extractHostFromRequest(normalizedRaw);
            boolean useHttps = true;
            int port = 443;

            if (host.isBlank()) {
                String fallbackUrl = resolveUrlForRepeater(selected.primaryMethod());
                try {
                    java.net.URI uri = new java.net.URI(fallbackUrl);
                    host = uri.getHost() == null ? "" : uri.getHost();
                    useHttps = "https".equalsIgnoreCase(uri.getScheme());
                    port = uri.getPort() > 0 ? uri.getPort() : (useHttps ? 443 : 80);
                } catch (Exception ignored) {
                    host = selected.host() == null ? "" : selected.host();
                }
            }

            if (host.isBlank()) {
                JOptionPane.showMessageDialog(this, "Cannot resolve target host from request.", "Missing host", JOptionPane.ERROR_MESSAGE);
                return;
            }

            HttpRequest httpRequest = HttpRequest.httpRequest(
                    burp.api.montoya.http.HttpService.httpService(host, port, useHttps),
                    normalizedRaw
            );

            String tabName = "LH-" + selected.primaryMethod();
            if (tabName.length() > 30) tabName = tabName.substring(0, 30);
            api.repeater().sendToRepeater(httpRequest, tabName);

            byte[] sentBytes = normalizedRaw.getBytes(StandardCharsets.UTF_8);
                api.logging().logToOutput("[LogicHunter][repeater-bytes] suggestionId=" + selected.suggestionId()
                    + " host=" + host
                    + " bytes=" + sentBytes.length
                    + " base64=" + Base64.getEncoder().encodeToString(sentBytes));

            JOptionPane.showMessageDialog(this,
                    "Sent to Repeater tab: " + tabName + "\n\nExact captured request bytes were forwarded.",
                    "Sent to Repeater", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed to send to Repeater.", ex);
            JOptionPane.showMessageDialog(this, "Failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String extractHostFromRequest(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return "";
        }

        String[] lines = rawRequest.split("\\r?\\n");
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                break;
            }
            String lowered = line.toLowerCase(Locale.ROOT);
            if (!lowered.startsWith("host:")) {
                continue;
            }
            String host = line.substring(line.indexOf(':') + 1).trim();
            int colon = host.indexOf(':');
            if (colon > -1) {
                return host.substring(0, colon);
            }
            return host;
        }
        return "";
    }

    private String resolveUrlForRepeater(String methodName) {
        if (methodName == null || methodName.isBlank() || "(multiple)".equals(methodName)) {
            return "";
        }
        Optional<JsonRpcIndex.MethodDetails> details = index.snapshotMethodDetails(methodName);
        if (details.isPresent()) {
            JsonRpcRecord rawRecord = details.get().primaryRawRecord();
            if (rawRecord != null && rawRecord.request() != null) {
                String url = rawRecord.request().url();
                return url == null ? "" : url;
            }
        }
        return "";
    }

    private void exportSelectedSuggestion() {
        AttackSuggestion selected = getSelectedSuggestion();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select a suggestion first.", "No selection", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        ObjectNode payload;
        try {
            payload = suggestionService.buildManualExportBundle(selected.suggestionId());

            // Enrich export with full auth context
            AuthContextStore.AuthContext adminCtx = authContextStore.firstContextByRole(RoleType.ADMIN);
            AuthContextStore.AuthContext lowPrivCtx = authContextStore.firstContextByRole(RoleType.LOW_PRIV);

            if (adminCtx != null) {
                ObjectNode adminNode = objectMapper.createObjectNode();
                adminNode.put("database", adminCtx.database());
                adminNode.put("userName", adminCtx.userName());
                adminNode.put("sessionId", adminCtx.sessionId());
                adminNode.put("lastUrl", adminCtx.lastSeenUrl());
                payload.set("adminContext", adminNode);
            }
            if (lowPrivCtx != null) {
                ObjectNode lowNode = objectMapper.createObjectNode();
                lowNode.put("database", lowPrivCtx.database());
                lowNode.put("userName", lowPrivCtx.userName());
                lowNode.put("sessionId", lowPrivCtx.sessionId());
                lowNode.put("lastUrl", lowPrivCtx.lastSeenUrl());
                payload.set("lowPrivContext", lowNode);
            }

            // Add cURL commands
            String curlLowPriv = CopyablePayloadBuilder.buildCurlForSuggestion(selected, authContextStore, index);
            payload.put("curlCommand", curlLowPriv);

            String httpRequest = CopyablePayloadBuilder.buildHttpRequest(selected, authContextStore, index);
            payload.put("rawHttpRequest", httpRequest);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not build export: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
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
            JOptionPane.showMessageDialog(this, "Suggestion exported to: " + destination.getAbsolutePath(), "Export complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            api.logging().logToError("Failed exporting attack suggestion bundle.", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private AttackSuggestion getSelectedSuggestion() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        return tableModel.rowAt(modelRow);
    }

    private static void copyToClipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception ignored) {
            // Clipboard access may fail in some environments.
        }
    }

    private static String truncateForDisplay(String value, int maxLen) {
        if (value == null) return "(empty)";
        return value.length() <= maxLen ? value : value.substring(0, maxLen) + "\n... (truncated)";
    }

    private static String escapeHtml(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static JTextArea buildMonoTextArea() {
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
                JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column
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
