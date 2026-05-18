package com.methodminer.ui;

import com.methodminer.comparison.RoleComparisonEngine;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.SessionProfile;
import com.methodminer.core.repository.SurfaceRepository;
import com.methodminer.export.*;
import com.methodminer.payload.PayloadAssembler;
import com.methodminer.payload.PayloadAssemblyResult;
import com.methodminer.risk.RiskSignalGenerator;
import com.methodminer.risk.RiskSignalResult;
import com.methodminer.session.SessionRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Export dialog that generates and presents intelligence artifacts.
 *
 * <p>Provides options to preview, copy Markdown, or save all artifacts to disk.
 */
public final class ExportDialog extends JDialog {

    private final SurfaceRepository surfaceRepository;
    private final SessionRepository sessionRepository;
    private final RoleComparisonEngine comparisonEngine;
    private final RiskSignalGenerator signalGenerator;
    private final PayloadAssembler payloadAssembler;
    private final IntelligenceExporter exporter;

    private final JCheckBox cbSessions;
    private final JCheckBox cbComparisons;
    private final JCheckBox cbSignals;
    private final JCheckBox cbPayloads;
    private final JCheckBox cbSchema;
    private final JCheckBox cbTimestamps;
    private final JCheckBox cbRedact;
    private final JTextField projectNameField;
    private final JTextArea previewArea;
    private final JLabel statusLabel;

    private ExportResult lastResult;

    public ExportDialog(Frame owner,
                        SurfaceRepository surfaceRepository,
                        SessionRepository sessionRepository,
                        RoleComparisonEngine comparisonEngine,
                        RiskSignalGenerator signalGenerator,
                        PayloadAssembler payloadAssembler) {
        super(owner, "Method Miner — Export Intelligence", true);
        this.surfaceRepository = Objects.requireNonNull(surfaceRepository);
        this.sessionRepository = sessionRepository;
        this.comparisonEngine = comparisonEngine;
        this.signalGenerator = signalGenerator;
        this.payloadAssembler = payloadAssembler;
        this.exporter = new IntelligenceExporter();

        setSize(800, 600);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(8, 8));

        // Options panel
        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder("Export Options"));

        cbSessions = new JCheckBox("Sessions", true);
        cbComparisons = new JCheckBox("Comparisons", true);
        cbSignals = new JCheckBox("Risk Signals", true);
        cbPayloads = new JCheckBox("Payloads", true);
        cbSchema = new JCheckBox("Schema Summary", true);
        cbTimestamps = new JCheckBox("Timestamps", true);
        cbRedact = new JCheckBox("Redact Placeholders", false);

        optionsPanel.add(cbSessions);
        optionsPanel.add(cbComparisons);
        optionsPanel.add(cbSignals);
        optionsPanel.add(cbPayloads);
        optionsPanel.add(cbSchema);
        optionsPanel.add(cbTimestamps);
        optionsPanel.add(cbRedact);
        optionsPanel.add(Box.createVerticalStrut(8));

        JPanel namePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        namePanel.add(new JLabel("Project:"));
        projectNameField = new JTextField("methodminer", 15);
        namePanel.add(projectNameField);
        optionsPanel.add(namePanel);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton generateBtn = new JButton("Generate Export");
        generateBtn.addActionListener(e -> onGenerate());
        buttonPanel.add(generateBtn);

        JButton copyMdBtn = new JButton("Copy Markdown");
        copyMdBtn.addActionListener(e -> onCopyMarkdown());
        buttonPanel.add(copyMdBtn);

        JButton saveAllBtn = new JButton("Save All...");
        saveAllBtn.addActionListener(e -> onSaveAll());
        buttonPanel.add(saveAllBtn);

        statusLabel = new JLabel(" ");
        buttonPanel.add(statusLabel);

        // Left panel
        JPanel leftPanel = new JPanel(new BorderLayout(4, 4));
        leftPanel.setPreferredSize(new Dimension(220, 0));
        leftPanel.add(optionsPanel, BorderLayout.NORTH);
        leftPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Preview area
        previewArea = new JTextArea();
        previewArea.setEditable(false);
        previewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewArea.setBorder(new EmptyBorder(6, 6, 6, 6));
        previewArea.setText("Click 'Generate Export' to preview the report.");

        JScrollPane previewScroll = new JScrollPane(previewArea);
        previewScroll.setBorder(BorderFactory.createTitledBorder("Preview"));

        // Layout
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, previewScroll);
        split.setResizeWeight(0.0);
        split.setDividerLocation(230);

        add(split, BorderLayout.CENTER);
    }

    private ExportOptions buildOptions() {
        return new ExportOptions(
                cbSessions.isSelected(),
                cbComparisons.isSelected(),
                cbSignals.isSelected(),
                cbPayloads.isSelected(),
                cbSchema.isSelected(),
                cbTimestamps.isSelected(),
                cbRedact.isSelected(),
                projectNameField.getText().trim()
        );
    }

    private void onGenerate() {
        ExportOptions options = buildOptions();
        ApiSurface surface = surfaceRepository.snapshot();
        List<SessionProfile> sessions = sessionRepository != null ? sessionRepository.snapshot() : List.of();
        RoleComparisonResult comparison = comparisonEngine != null ? comparisonEngine.compare() : null;
        RiskSignalResult signals = null;
        PayloadAssemblyResult payloads = null;

        if (signalGenerator != null && comparison != null) {
            signals = signalGenerator.generate(comparison);
        }
        if (payloadAssembler != null && signals != null) {
            payloads = payloadAssembler.assemble(signals);
        }

        lastResult = exporter.export(surface, sessions, comparison, signals, payloads, options);

        // Show Markdown report in preview
        ExportArtifact mdArtifact = lastResult.artifacts().stream()
                .filter(a -> a.format() == ExportFormat.MARKDOWN)
                .findFirst().orElse(null);

        if (mdArtifact != null) {
            previewArea.setText(mdArtifact.content());
            previewArea.setCaretPosition(0);
        }

        statusLabel.setText(lastResult.summary());
    }

    private void onCopyMarkdown() {
        if (lastResult == null) {
            onGenerate();
        }
        if (lastResult == null) return;

        ExportArtifact mdArtifact = lastResult.artifacts().stream()
                .filter(a -> a.format() == ExportFormat.MARKDOWN)
                .findFirst().orElse(null);

        if (mdArtifact != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(mdArtifact.content()), null);
            statusLabel.setText("Markdown copied to clipboard.");
        }
    }

    private void onSaveAll() {
        if (lastResult == null) {
            onGenerate();
        }
        if (lastResult == null || lastResult.artifacts().isEmpty()) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Select export directory");

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            Path dir = chooser.getSelectedFile().toPath();
            int saved = 0;
            for (ExportArtifact artifact : lastResult.artifacts()) {
                try {
                    Files.writeString(dir.resolve(artifact.fileName()),
                            artifact.content(), StandardCharsets.UTF_8);
                    saved++;
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(this,
                            "Error writing " + artifact.fileName() + ": " + ex.getMessage(),
                            "Export Error", JOptionPane.ERROR_MESSAGE);
                }
            }
            statusLabel.setText("Saved " + saved + " files to " + dir.getFileName());
        }
    }
}
