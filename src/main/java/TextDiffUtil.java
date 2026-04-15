import java.util.ArrayList;
import java.util.List;

public final class TextDiffUtil {
    private TextDiffUtil() {
    }

    public static String summarizeDifferences(String left, String right, String label) {
        String leftValue = left == null ? "" : left;
        String rightValue = right == null ? "" : right;

        if (leftValue.equals(rightValue)) {
            return label + ": no differences.";
        }

        String[] leftLines = leftValue.split("\\R", -1);
        String[] rightLines = rightValue.split("\\R", -1);

        int max = Math.max(leftLines.length, rightLines.length);
        int changed = 0;
        List<String> examples = new ArrayList<>();

        for (int i = 0; i < max; i++) {
            String leftLine = i < leftLines.length ? leftLines[i] : "";
            String rightLine = i < rightLines.length ? rightLines[i] : "";
            if (!leftLine.equals(rightLine)) {
                changed++;
                if (examples.size() < 10) {
                    examples.add("Line " + (i + 1) + "\n- " + truncate(leftLine) + "\n+ " + truncate(rightLine));
                }
            }
        }

        StringBuilder builder = new StringBuilder();
        builder.append(label)
                .append(": ")
                .append(changed)
                .append(" changed line(s), left=")
                .append(leftLines.length)
                .append(" line(s), right=")
                .append(rightLines.length)
                .append(" line(s).");

        if (!examples.isEmpty()) {
            builder.append("\n\nExamples:\n");
            for (String example : examples) {
                builder.append(example).append("\n\n");
            }
        }

        return builder.toString().trim();
    }

    private static String truncate(String value) {
        if (value == null || value.isBlank()) {
            return "(empty)";
        }
        String trimmed = value.strip();
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 160) + "...";
    }
}
