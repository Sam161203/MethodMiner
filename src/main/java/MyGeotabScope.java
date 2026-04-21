import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class MyGeotabScope {
    private static final String ALLOWED_HOSTS_PROPERTY = "logichunter.allowedHosts";
    private static final String ALLOWED_HOSTS_ENV = "LOGICHUNTER_ALLOWED_HOSTS";

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

        List<String> allowedHosts = configuredAllowedHosts();
        if (allowedHosts.isEmpty()) {
            return true;
        }

        for (String allowed : allowedHosts) {
            if (hostMatchesRule(normalizedHost, allowed)) {
                return true;
            }
        }

        return false;
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

    private static List<String> configuredAllowedHosts() {
        String configured = System.getProperty(ALLOWED_HOSTS_PROPERTY, "");
        if (configured.isBlank()) {
            configured = System.getenv(ALLOWED_HOSTS_ENV);
        }

        if (configured == null || configured.isBlank()) {
            return List.of();
        }

        String[] tokens = configured.split(",");
        List<String> normalized = new ArrayList<>();
        for (String token : tokens) {
            String value = normalizeHost(token);
            if (!value.isBlank()) {
                normalized.add(value);
            }
        }
        return normalized;
    }

    private static boolean hostMatchesRule(String host, String rule) {
        if (host.equals(rule)) {
            return true;
        }

        if (rule.startsWith("*.")) {
            String suffix = rule.substring(1);
            return !suffix.isBlank() && host.endsWith(suffix);
        }

        return false;
    }
}
