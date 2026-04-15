import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

public final class MyGeotabScope {
    private static final Pattern ALLOWED_HOST_PATTERN =
            Pattern.compile("^(?:bugcrowd\\.geotab\\.com|bugcrowd(?:[5-9]|10|11)\\.geotab\\.com)$", Pattern.CASE_INSENSITIVE);

    private MyGeotabScope() {
    }

    public static boolean isAllowedUrl(String url) {
        return isAllowedHost(extractHost(url));
    }

    public static boolean isAllowedHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }

        String normalizedHost = normalizeHost(host);
        if (normalizedHost.isBlank()) {
            return false;
        }

        return ALLOWED_HOST_PATTERN.matcher(normalizedHost).matches();
    }

    public static String extractHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            URI uri = URI.create(url);
            return uri.getHost() == null ? "" : normalizeHost(uri.getHost());
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String normalizeHost(String host) {
        if (host == null || host.isBlank()) {
            return "";
        }

        String normalized = host.trim().toLowerCase(Locale.ROOT);

        // Allow Host header style values like "example.com:443".
        int colon = normalized.indexOf(':');
        if (colon > 0 && normalized.indexOf(']') < 0) {
            normalized = normalized.substring(0, colon);
        }

        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        return normalized;
    }
}
