package com.methodminer.ui;

import com.methodminer.core.events.EventBus;
import com.methodminer.core.events.SessionChangedEvent;
import com.methodminer.core.model.Role;
import com.methodminer.core.model.SessionProfile;
import com.methodminer.session.SessionRepository;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Session awareness panel that displays discovered authentication contexts.
 *
 * <p>Auto-refreshes when sessions are discovered via {@link SessionChangedEvent}.
 * Supports sorting, filtering by role/host, and free-text search.
 */
public final class SessionPanel extends JPanel {
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final SessionRepository sessionRepository;
    private final SessionTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<SessionTableModel> sorter;
    private final JComboBox<String> roleFilter;
    private final JTextField hostFilter;
    private final JTextField searchField;

    public SessionPanel(EventBus eventBus, SessionRepository sessionRepository) {
        super(new BorderLayout(4, 4));
        this.sessionRepository = Objects.requireNonNull(sessionRepository, "sessionRepository");
        setBorder(BorderFactory.createTitledBorder("Sessions"));

        this.tableModel = new SessionTableModel();
        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.getTableHeader().setReorderingAllowed(false);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(65);  // Role
        table.getColumnModel().getColumn(1).setPreferredWidth(100); // Session ID
        table.getColumnModel().getColumn(2).setPreferredWidth(140); // Host
        table.getColumnModel().getColumn(3).setPreferredWidth(130); // Username
        table.getColumnModel().getColumn(4).setPreferredWidth(100); // Database
        table.getColumnModel().getColumn(5).setPreferredWidth(120); // Auth
        table.getColumnModel().getColumn(6).setPreferredWidth(50);  // Requests
        table.getColumnModel().getColumn(7).setPreferredWidth(70);  // Last Seen

        // Toolbar
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        JButton markAdmin = new JButton("Mark ADMIN");
        markAdmin.addActionListener(e -> setSelectedRole(Role.ADMIN));
        JButton markLowPriv = new JButton("Mark LOW_PRIV");
        markLowPriv.addActionListener(e -> setSelectedRole(Role.LOW_PRIV));
        JButton clearRole = new JButton("Clear Role");
        clearRole.addActionListener(e -> setSelectedRole(Role.UNKNOWN));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshData());

        toolbar.add(markAdmin);
        toolbar.add(markLowPriv);
        toolbar.add(clearRole);
        toolbar.addSeparator(new Dimension(12, 0));
        toolbar.add(refresh);

        // Filter bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filterBar.add(new JLabel("Role:"));
        roleFilter = new JComboBox<>(new String[]{"ALL", "UNKNOWN", "ADMIN", "LOW_PRIV", "CUSTOM"});
        roleFilter.addActionListener(e -> applyFilters());
        filterBar.add(roleFilter);

        filterBar.add(new JLabel("Host:"));
        hostFilter = new JTextField(12);
        hostFilter.addActionListener(e -> applyFilters());
        filterBar.add(hostFilter);

        filterBar.add(new JLabel("Search:"));
        searchField = new JTextField(14);
        searchField.addActionListener(e -> applyFilters());
        filterBar.add(searchField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyFilters());
        filterBar.add(filterBtn);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbar, BorderLayout.NORTH);
        topPanel.add(filterBar, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        // Subscribe to session events
        eventBus.subscribe(SessionChangedEvent.class, event ->
                SwingUtilities.invokeLater(this::refreshData));

        // Initial load
        refreshData();
    }

    private void refreshData() {
        List<SessionProfile> profiles = sessionRepository.snapshot();
        tableModel.setData(profiles);
        applyFilters();
    }

    private void setSelectedRole(Role role) {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        UUID id = tableModel.getSessionId(modelRow);
        if (id == null) return;

        sessionRepository.setRole(id, role);
        refreshData();
    }

    private void applyFilters() {
        List<RowFilter<SessionTableModel, Integer>> filters = new ArrayList<>();

        String roleValue = (String) roleFilter.getSelectedItem();
        if (roleValue != null && !"ALL".equals(roleValue)) {
            filters.add(RowFilter.regexFilter("^" + roleValue + "$", 0));
        }

        String hostText = hostFilter.getText().trim();
        if (!hostText.isBlank()) {
            filters.add(RowFilter.regexFilter("(?i)" + escapeRegex(hostText), 2));
        }

        String searchText = searchField.getText().trim();
        if (!searchText.isBlank()) {
            // Search across username (3) and database (4) columns
            filters.add(RowFilter.regexFilter("(?i)" + escapeRegex(searchText)));
        }

        if (filters.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private static String escapeRegex(String text) {
        return text.replaceAll("([\\\\\\[\\]{}()*+?.^$|])", "\\\\$1");
    }

    // ---- Table Model -------------------------------------------------------

    private static final class SessionTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
                "Role", "Session ID", "Host", "Username", "Database",
                "Auth Mechanisms", "Requests", "Last Seen"
        };

        private List<SessionProfile> data = List.of();

        void setData(List<SessionProfile> profiles) {
            this.data = profiles == null ? List.of() : List.copyOf(profiles);
            fireTableDataChanged();
        }

        UUID getSessionId(int row) {
            if (row < 0 || row >= data.size()) return null;
            return data.get(row).id();
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 6) return Integer.class; // Requests
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= data.size()) return "";
            SessionProfile p = data.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> p.role().name();
                case 1 -> shortenId(p.id());
                case 2 -> p.host();
                case 3 -> p.username();
                case 4 -> p.database();
                case 5 -> formatSet(p.authMechanisms());
                case 6 -> p.requestCount();
                case 7 -> formatTime(p.lastSeen());
                default -> "";
            };
        }

        private static String shortenId(UUID id) {
            if (id == null) return "";
            String s = id.toString();
            return s.length() > 8 ? s.substring(0, 8) + "…" : s;
        }

        private static String formatSet(Set<String> set) {
            if (set == null || set.isEmpty()) return "";
            return set.stream().sorted().collect(Collectors.joining(", "));
        }

        private static String formatTime(Instant t) {
            if (t == null) return "";
            return TIME_FMT.format(t);
        }
    }
}
