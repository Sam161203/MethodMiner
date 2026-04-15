import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MyGeotabScopeTest {

    @Test
    void allowsCurrentBugcrowdHostVariants() {
        assertTrue(MyGeotabScope.isAllowedHost("bugcrowd.geotab.com"));
        assertTrue(MyGeotabScope.isAllowedHost("bugcrowd7.geotab.com"));
        assertTrue(MyGeotabScope.isAllowedHost("bugcrowd10.geotab.com"));
    }

    @Test
    void allowsHostWithPortByNormalizing() {
        assertTrue(MyGeotabScope.isAllowedHost("bugcrowd.geotab.com:443"));
    }

    @Test
    void rejectsOutOfScopeHosts() {
        assertFalse(MyGeotabScope.isAllowedHost("example.com"));
        assertFalse(MyGeotabScope.isAllowedHost("api.bugcrowd.com"));
    }

    @Test
    void extractsNormalizedHostFromUrl() {
        assertTrue(MyGeotabScope.isAllowedUrl("https://bugcrowd.geotab.com/apiv1"));
        assertFalse(MyGeotabScope.isAllowedUrl("https://example.com/apiv1"));
    }
}
