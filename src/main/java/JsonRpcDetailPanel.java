import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Font;

public final class JsonRpcDetailPanel extends JPanel {
    private final JTextArea requestArea = buildTextArea();
    private final JTextArea responseArea = buildTextArea();
    private final JTextArea metadataArea = buildTextArea();
    private final JTextArea rawRecordArea = buildTextArea();

    public JsonRpcDetailPanel() {
        super(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Method Details"));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Sample Request", new JScrollPane(requestArea));
        tabs.addTab("Sample Response", new JScrollPane(responseArea));
        tabs.addTab("Normalized Metadata", new JScrollPane(metadataArea));
        tabs.addTab("Raw JSON Record", new JScrollPane(rawRecordArea));

        add(tabs, BorderLayout.CENTER);
    }

    public void clear() {
        requestArea.setText("");
        responseArea.setText("");
        metadataArea.setText("");
        rawRecordArea.setText("");
    }

    public void showMethodDetails(JsonRpcIndex.MethodDetails details, ObjectMapper objectMapper) {
        if (details == null) {
            clear();
            return;
        }

        JsonRpcRecord raw = details.primaryRawRecord();
        requestArea.setText(raw == null ? "" : raw.request().rawHttpText());

        if (raw == null || !raw.response().present()) {
            responseArea.setText("(Response missing)");
        } else {
            responseArea.setText(raw.response().rawHttpText());
        }

        try {
            String metadataPretty = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(details.toMetadataJson(objectMapper));
            metadataArea.setText(metadataPretty);
        } catch (Exception ex) {
            metadataArea.setText("Unable to render metadata: " + ex.getMessage());
        }

        try {
            if (raw == null) {
                rawRecordArea.setText("");
            } else {
                String rawPretty = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(raw.toJson(objectMapper));
                rawRecordArea.setText(rawPretty);
            }
        } catch (Exception ex) {
            rawRecordArea.setText("Unable to render raw record: " + ex.getMessage());
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
}
