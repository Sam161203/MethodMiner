import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MyGeotabScopeTest {
    private static final String ALLOWED_HOSTS_PROPERTY = "logichunter.allowedHosts";

    @Test
    void allowsAnyHostWhenNoFilterConfigured() {
        String previous = System.getProperty(ALLOWED_HOSTS_PROPERTY);
        try {
            System.clearProperty(ALLOWED_HOSTS_PROPERTY);
            assertTrue(MyGeotabScope.isAllowedHost("api.example.com"));
            assertTrue(MyGeotabScope.isAllowedHost("tenant-a.internal.example"));
        } finally {
            restoreAllowedHostsProperty(previous);
        }
    }

    @Test
    void honorsConfiguredAllowList() {
        String previous = System.getProperty(ALLOWED_HOSTS_PROPERTY);
        try {
            System.setProperty(ALLOWED_HOSTS_PROPERTY, "api.example.com,*.trusted.example.net");
            assertTrue(MyGeotabScope.isAllowedHost("api.example.com"));
            assertTrue(MyGeotabScope.isAllowedHost("tenant.trusted.example.net"));
            assertTrue(MyGeotabScope.isAllowedHost("api.example.com:443"));
            assertFalse(MyGeotabScope.isAllowedHost("api.other.com"));
        } finally {
            restoreAllowedHostsProperty(previous);
        }
    }

    @Test
    void extractsNormalizedHostFromUrl() {
        String previous = System.getProperty(ALLOWED_HOSTS_PROPERTY);
        try {
            System.setProperty(ALLOWED_HOSTS_PROPERTY, "api.example.com");
            assertTrue(MyGeotabScope.isAllowedUrl("https://api.example.com/jsonrpc"));
            assertFalse(MyGeotabScope.isAllowedUrl("https://api.other.com/jsonrpc"));
        } finally {
            restoreAllowedHostsProperty(previous);
        }
    }

    private void restoreAllowedHostsProperty(String previous) {
        if (previous == null) {
            System.clearProperty(ALLOWED_HOSTS_PROPERTY);
            return;
        }
        System.setProperty(ALLOWED_HOSTS_PROPERTY, previous);
    }
}
