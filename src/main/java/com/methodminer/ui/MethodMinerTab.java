package com.methodminer.ui;

import com.methodminer.comparison.RoleComparisonEngine;
import com.methodminer.core.ProjectLifecycleManager;
import com.methodminer.core.events.EventBus;
import com.methodminer.core.events.ProjectResetEvent;
import com.methodminer.core.events.SurfaceChangedEvent;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.repository.SurfaceRepository;
import com.methodminer.payload.PayloadAssembler;
import com.methodminer.risk.RiskSignalGenerator;
import com.methodminer.session.SessionRepository;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Production-quality, passive UI for the unified Method Miner experience.
 *
 * <p>Features:
 * <ul>
 *   <li>Navigation tree with schema and evidence panels</li>
 *   <li>Toolbar with Clear Project, Clear Sessions, Refresh Analysis, Export</li>
 *   <li>Status bar with live counts and last refresh time</li>
 *   <li>Debounced refresh to avoid excessive recomputation</li>
 *   <li>Tooltips on all toolbar buttons</li>
 * </ul>
 */
public final class MethodMinerTab extends JPanel {
    public static final String TAB_TITLE = "Method Miner";

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());
    private static final int DEBOUNCE_MS = 300;

    private final EventBus eventBus;
    private final SurfaceRepository surfaceRepository;
    private final SessionRepository sessionRepository;
    private final RoleComparisonEngine comparisonEngine;
    private final RiskSignalGenerator riskSignalGenerator;
    private final PayloadAssembler payloadAssembler;
    private final ProjectLifecycleManager lifecycleManager;
    private final SurfaceViewModel viewModel;

    private final AtomicReference<ApiSurface> currentSurface;

    private final JTree navigationTree;
    private final DefaultTreeModel navigationTreeModel;
    private final JTextArea schemaTextArea;
    private final JTextArea evidenceTextArea;

    // Status bar labels
    private final JLabel statusServices;
    private final JLabel statusOperations;
    private final JLabel statusObservations;
    private final JLabel statusSessions;
    private final JLabel statusLastRefresh;

    // Debounce timer — coalesces rapid SurfaceChangedEvents
    private final Timer debounceTimer;

    private volatile TreeNodeFactory.TreeNodeData selectedOperation;
    private volatile boolean refreshing;

    public MethodMinerTab(EventBus eventBus,
                          SurfaceRepository surfaceRepository,
                          SessionRepository sessionRepository,
                          ProjectLifecycleManager lifecycleManager) {
        this(
                eventBus,
                surfaceRepository,
                Objects.requireNonNull(sessionRepository, "sessionRepository"),
                new RoleComparisonEngine(surfaceRepository, sessionRepository),
                new RiskSignalGenerator(),
                new PayloadAssembler(surfaceRepository, sessionRepository),
                lifecycleManager
        );
    }

    public MethodMinerTab(EventBus eventBus, SurfaceRepository surfaceRepository,
                          SessionRepository sessionRepository, RoleComparisonEngine comparisonEngine,
                          RiskSignalGenerator riskSignalGenerator, PayloadAssembler payloadAssembler) {
        this(
                eventBus,
                surfaceRepository,
                sessionRepository,
                comparisonEngine,
                riskSignalGenerator,
                payloadAssembler,
                new ProjectLifecycleManager(surfaceRepository, sessionRepository, eventBus)
        );
    }

    public MethodMinerTab(EventBus eventBus, SurfaceRepository surfaceRepository,
                          SessionRepository sessionRepository, RoleComparisonEngine comparisonEngine,
                          RiskSignalGenerator riskSignalGenerator, PayloadAssembler payloadAssembler,
                          ProjectLifecycleManager lifecycleManager) {
        super(new BorderLayout(8, 8));
        this.eventBus = Objects.requireNonNull(eventBus, "eventBus");
        this.surfaceRepository = Objects.requireNonNull(surfaceRepository, "surfaceRepository");
        this.sessionRepository = sessionRepository; // may be null during tests
        this.comparisonEngine = comparisonEngine;    // may be null during tests
        this.riskSignalGenerator = riskSignalGenerator; // may be null during tests
        this.payloadAssembler = payloadAssembler;    // may be null during tests
        this.lifecycleManager = Objects.requireNonNull(lifecycleManager, "lifecycleManager");
        this.viewModel = new SurfaceViewModel(new TreeNodeFactory());

        ApiSurface initialSurface = this.surfaceRepository.snapshot();
        this.currentSurface = new AtomicReference<>(initialSurface);

        DefaultMutableTreeNode root = viewModel.buildNavigationTree(initialSurface);
        this.navigationTreeModel = new DefaultTreeModel(root);
        this.navigationTree = new JTree(navigationTreeModel);
        navigationTree.setRootVisible(true);
        navigationTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        navigationTree.addTreeSelectionListener(event -> onTreeSelectionChanged());

        this.schemaTextArea = createReadOnlyTextArea();
        this.evidenceTextArea = createReadOnlyTextArea();
        schemaTextArea.setText("Select an operation to view its schema.");
        evidenceTextArea.setText("Select an operation to view evidence.");

        // Status bar labels
        this.statusServices = new JLabel("Services: 0");
        this.statusOperations = new JLabel("Operations: 0");
        this.statusObservations = new JLabel("Observations: 0");
        this.statusSessions = new JLabel("Sessions: 0");
        this.statusLastRefresh = new JLabel("Last refresh: —");

        // Debounce timer — fires on EDT, non-repeating
        this.debounceTimer = new Timer(DEBOUNCE_MS, e -> applyPendingSurfaceUpdate());
        this.debounceTimer.setRepeats(false);

        setBorder(new EmptyBorder(8, 8, 8, 8));

        add(buildToolbar(), BorderLayout.NORTH);
        add(buildContentSplitPane(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        expandInitialTree();
        updateStatusBar(initialSurface);
        subscribeToEvents();
    }

    // ---- Event Handling -----------------------------------------------------

    private void subscribeToEvents() {
        eventBus.subscribe(SurfaceChangedEvent.class, event -> onSurfaceChanged(event.surface()));
        eventBus.subscribe(ProjectResetEvent.class, event -> onProjectReset());
    }

    private void onSurfaceChanged(ApiSurface surface) {
        currentSurface.set(surface);
        // Debounce: restart the timer so rapid events coalesce
        SwingUtilities.invokeLater(() -> debounceTimer.restart());
    }

    /** Called by the debounce timer on the EDT. */
    private void applyPendingSurfaceUpdate() {
        ApiSurface surface = currentSurface.get();
        DefaultMutableTreeNode root = viewModel.buildNavigationTree(surface);
        applySurfaceUpdate(surface, root);
        updateStatusBar(surface);
    }

    private void onProjectReset() {
        SwingUtilities.invokeLater(() -> {
            ApiSurface surface = surfaceRepository.snapshot();
            currentSurface.set(surface);
            DefaultMutableTreeNode root = viewModel.buildNavigationTree(surface);
            applySurfaceUpdate(surface, root);
            updateStatusBar(surface);
        });
    }

    private void applySurfaceUpdate(ApiSurface surface, DefaultMutableTreeNode root) {
        refreshing = true;
        try {
            navigationTreeModel.setRoot(root);
            navigationTreeModel.reload();
            expandInitialTree();

            if (selectedOperation != null && selectedOperation.operationId() != null) {
                TreePath path = findOperationPath(root, selectedOperation.operationId());
                if (path != null) {
                    navigationTree.setSelectionPath(path);
                    navigationTree.scrollPathToVisible(path);
                }
            }

            refreshPanelsFromSelection();
        } finally {
            refreshing = false;
        }
    }

    // ---- Tree Selection -----------------------------------------------------

    private void onTreeSelectionChanged() {
        if (refreshing) {
            return;
        }

        TreePath selection = navigationTree.getSelectionPath();
        if (selection == null) {
            selectedOperation = null;
            refreshPanelsFromSelection();
            return;
        }

        Object last = selection.getLastPathComponent();
        if (!(last instanceof DefaultMutableTreeNode node)) {
            selectedOperation = null;
            refreshPanelsFromSelection();
            return;
        }

        Object userObject = node.getUserObject();
        if (userObject instanceof TreeNodeFactory.TreeNodeData data && data.kind() == TreeNodeFactory.NodeKind.OPERATION) {
            selectedOperation = data;
        } else {
            selectedOperation = null;
        }

        refreshPanelsFromSelection();
    }

    private void refreshPanelsFromSelection() {
        ApiSurface surface = currentSurface.get();
        TreeNodeFactory.TreeNodeData operation = selectedOperation;

        if (operation == null) {
            schemaTextArea.setText("Select an operation to view its schema.");
            evidenceTextArea.setText("Select an operation to view evidence.");
            return;
        }

        schemaTextArea.setText(viewModel.renderSchema(surface, operation));
        evidenceTextArea.setText(viewModel.renderEvidence(surface, operation));
    }

    // ---- Toolbar ------------------------------------------------------------

    private JComponent buildToolbar() {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        JLabel title = new JLabel("Method Miner");
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        toolbar.add(title);
        toolbar.addSeparator(new Dimension(12, 0));

        toolbar.add(toolbarButton("Clear Project", "Clear all data and start fresh (Ctrl+Shift+D)",
                this::onClearProject));
        toolbar.add(toolbarButton("Clear Sessions", "Clear session profiles and role labels",
                this::onClearSessions));
        toolbar.addSeparator(new Dimension(8, 0));
        toolbar.add(toolbarButton("Refresh", "Recompute analysis from current data (F5)",
                this::onRefreshAnalysis));

        toolbar.add(Box.createHorizontalGlue());

        toolbar.add(toolbarButton("Export", "Export intelligence to Markdown, JSON, CSV...",
                this::openExportDialog));

        return toolbar;
    }

    private static JButton toolbarButton(String label, String tooltip, Runnable action) {
        JButton button = new JButton(label);
        button.setToolTipText(tooltip);
        button.addActionListener(e -> action.run());
        return button;
    }

    // ---- Toolbar Actions ----------------------------------------------------

    private void onClearProject() {
        int choice = JOptionPane.showConfirmDialog(this,
                "Clear all project data? This cannot be undone.\nObservations, sessions, and analysis will be removed.",
                "Clear Project", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice == JOptionPane.OK_OPTION) {
            lifecycleManager.clearProject();
        }
    }

    private void onClearSessions() {
        int choice = JOptionPane.showConfirmDialog(this,
                "Clear all session profiles and role labels?\nObservations and API surface data will be preserved.",
                "Clear Sessions", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice == JOptionPane.OK_OPTION) {
            lifecycleManager.clearSessions();
        }
    }

    private void onRefreshAnalysis() {
        lifecycleManager.refreshAnalysis();
    }

    private void openExportDialog() {
        Frame frame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, this);
        ExportDialog dialog = new ExportDialog(frame, surfaceRepository, sessionRepository,
                comparisonEngine, riskSignalGenerator, payloadAssembler);
        dialog.setVisible(true);
    }

    // ---- Status Bar ---------------------------------------------------------

    private JComponent buildStatusBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, getBackground().darker()),
                new EmptyBorder(2, 4, 2, 4)));

        Font statusFont = new Font(Font.SANS_SERIF, Font.PLAIN, 11);
        for (JLabel label : new JLabel[]{statusServices, statusOperations, statusObservations, statusSessions, statusLastRefresh}) {
            label.setFont(statusFont);
            bar.add(label);
            bar.add(new JLabel("│"));
        }
        // Remove trailing separator
        bar.remove(bar.getComponentCount() - 1);
        return bar;
    }

    private void updateStatusBar(ApiSurface surface) {
        int serviceCount = surface.services().size();
        int operationCount = surface.services().stream()
                .flatMap(s -> s.endpoints().stream())
                .mapToInt(ep -> ep.operations().size()).sum();
        int observationCount = surface.observations().size();
        int sessionCount = sessionRepository != null ? sessionRepository.snapshot().size() : 0;

        statusServices.setText("Services: " + serviceCount);
        statusOperations.setText("Operations: " + operationCount);
        statusObservations.setText("Observations: " + observationCount);
        statusSessions.setText("Sessions: " + sessionCount);
        statusLastRefresh.setText("Last refresh: " + TIME_FMT.format(Instant.now()));
    }

    // ---- Layout Builders ----------------------------------------------------

    private JSplitPane buildContentSplitPane() {
        JSplitPane split = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                buildNavigationTreePanel(),
                buildRightSideSplitPane()
        );
        split.setResizeWeight(0.25);
        split.setOneTouchExpandable(true);
        split.setBorder(null);
        return split;
    }

    private JComponent buildNavigationTreePanel() {
        JPanel panel = titledPanel("Navigation Tree");

        panel.add(new JScrollPane(navigationTree), BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildRightSideSplitPane() {
        JSplitPane bottom = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                buildEvidencePanel(),
                buildRecommendationsPanel()
        );
        bottom.setResizeWeight(0.5);
        bottom.setOneTouchExpandable(true);
        bottom.setBorder(null);

        JSplitPane vertical = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                buildSchemaPanel(),
                bottom
        );
        vertical.setResizeWeight(0.6);
        vertical.setOneTouchExpandable(true);
        vertical.setBorder(null);
        return vertical;
    }

    private JComponent buildSchemaPanel() {
        JPanel panel = titledPanel("Schema Panel");
        panel.add(new JScrollPane(schemaTextArea), BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildEvidencePanel() {
        JPanel panel = titledPanel("Evidence Panel");
        panel.add(new JScrollPane(evidenceTextArea), BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildRecommendationsPanel() {
        if (sessionRepository != null || comparisonEngine != null || riskSignalGenerator != null || payloadAssembler != null) {
            JTabbedPane tabs = new JTabbedPane(JTabbedPane.BOTTOM);
            if (riskSignalGenerator != null && comparisonEngine != null) {
                tabs.addTab("Risk Signals", new RiskSignalsPanel(eventBus, comparisonEngine, riskSignalGenerator));
            }
            if (payloadAssembler != null && comparisonEngine != null && riskSignalGenerator != null) {
                tabs.addTab("Payloads", new PayloadsPanel(eventBus, comparisonEngine, riskSignalGenerator, payloadAssembler));
            }
            if (comparisonEngine != null) {
                tabs.addTab("Comparison", new ComparisonPanel(eventBus, comparisonEngine));
            }
            if (sessionRepository != null) {
                tabs.addTab("Sessions", new SessionPanel(eventBus, sessionRepository));
            }
            return tabs;
        }
        JPanel panel = titledPanel("Recommendations Panel");
        panel.add(placeholderTextArea("No analysis data yet. Capture traffic with Burp Suite to begin."), BorderLayout.CENTER);
        return panel;
    }

    // ---- Utility Methods ----------------------------------------------------

    private static JPanel titledPanel(String title) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    private static JComponent placeholderTextArea(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(6, 6, 6, 6));
        return new JScrollPane(area);
    }

    private static JTextArea createReadOnlyTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(6, 6, 6, 6));
        return area;
    }

    private void expandInitialTree() {
        navigationTree.expandRow(0);
        for (int i = 0; i < Math.min(4, navigationTree.getRowCount()); i++) {
            navigationTree.expandRow(i);
        }
    }

    private static TreePath findOperationPath(DefaultMutableTreeNode root, UUID operationId) {
        if (root == null || operationId == null) {
            return null;
        }

        Deque<DefaultMutableTreeNode> queue = new ArrayDeque<>();
        queue.add(root);
        while (!queue.isEmpty()) {
            DefaultMutableTreeNode node = queue.removeFirst();
            Object userObject = node.getUserObject();
            if (userObject instanceof TreeNodeFactory.TreeNodeData data
                    && data.kind() == TreeNodeFactory.NodeKind.OPERATION
                    && operationId.equals(data.operationId())) {
                return new TreePath(node.getPath());
            }

            for (int i = 0; i < node.getChildCount(); i++) {
                Object child = node.getChildAt(i);
                if (child instanceof DefaultMutableTreeNode childNode) {
                    queue.add(childNode);
                }
            }
        }

        return null;
    }
}
