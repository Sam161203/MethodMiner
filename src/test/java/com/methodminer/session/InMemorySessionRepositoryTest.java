package com.methodminer.session;

import com.methodminer.core.model.ConfidenceLevel;
import com.methodminer.core.model.Role;
import com.methodminer.core.model.SessionProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link InMemorySessionRepository}.
 */
class InMemorySessionRepositoryTest {

    private InMemorySessionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new InMemorySessionRepository();
    }

    @Test
    void newFingerprintCreatesProfile() {
        SessionFingerprint fp = new SessionFingerprint(
                "api.example.com", "Bearer", "abcdef0123456789",
                "admin@test.com", "tenant-a",
                Set.of(), Set.of("Authorization"), Map.of()
        );

        SessionProfile profile = repository.upsert(fp, Instant.now());

        assertNotNull(profile);
        assertEquals("api.example.com", profile.host());
        assertEquals("admin@test.com", profile.username());
        assertEquals("tenant-a", profile.database());
        assertEquals(Role.UNKNOWN, profile.role());
        assertEquals(1, profile.requestCount());
        assertTrue(profile.authMechanisms().contains("Bearer"));
        assertTrue(profile.authFingerprints().contains("abcdef0123456789"));
        assertEquals(ConfidenceLevel.HIGH, profile.confidence());
    }

    @Test
    void sameFingerprintIncrementsCount() {
        SessionFingerprint fp = new SessionFingerprint(
                "api.example.com", "Cookie", "1234567890123456",
                "", "", Set.of("session"), Set.of(), Map.of()
        );

        Instant t1 = Instant.parse("2025-01-01T00:00:00Z");
        Instant t2 = Instant.parse("2025-01-01T00:01:00Z");

        SessionProfile first = repository.upsert(fp, t1);
        assertEquals(1, first.requestCount());

        SessionProfile second = repository.upsert(fp, t2);
        assertEquals(2, second.requestCount());
        assertEquals(t2, second.lastSeen());
        assertEquals(t1, second.firstSeen());
    }

    @Test
    void setRoleChangesRole() {
        SessionFingerprint fp = new SessionFingerprint(
                "host.com", "Bearer", "aabbccdd11223344",
                "user", "", Set.of(), Set.of("Authorization"), Map.of()
        );
        SessionProfile profile = repository.upsert(fp, Instant.now());
        assertEquals(Role.UNKNOWN, profile.role());

        assertTrue(repository.setRole(profile.id(), Role.ADMIN));
        Optional<SessionProfile> updated = repository.findById(profile.id());
        assertTrue(updated.isPresent());
        assertEquals(Role.ADMIN, updated.get().role());
    }

    @Test
    void snapshotReturnsAllProfilesSortedByLastSeen() {
        SessionFingerprint fp1 = new SessionFingerprint(
                "host1.com", "Bearer", "aaaa111122223333",
                "", "", Set.of(), Set.of(), Map.of()
        );
        SessionFingerprint fp2 = new SessionFingerprint(
                "host2.com", "Cookie", "bbbb444455556666",
                "", "", Set.of("sid"), Set.of(), Map.of()
        );

        repository.upsert(fp1, Instant.parse("2025-01-01T00:00:00Z"));
        repository.upsert(fp2, Instant.parse("2025-01-02T00:00:00Z"));

        List<SessionProfile> snapshot = repository.snapshot();
        assertEquals(2, snapshot.size());
        // Most recent first
        assertEquals("host2.com", snapshot.get(0).host());
        assertEquals("host1.com", snapshot.get(1).host());
    }

    @Test
    void findByIdReturnsProfile() {
        SessionFingerprint fp = new SessionFingerprint(
                "test.com", "Bearer", "ffff000011112222",
                "testuser", "testdb", Set.of(), Set.of("Authorization"), Map.of()
        );
        SessionProfile profile = repository.upsert(fp, Instant.now());

        Optional<SessionProfile> found = repository.findById(profile.id());
        assertTrue(found.isPresent());
        assertEquals(profile.id(), found.get().id());

        // Non-existent ID
        assertTrue(repository.findById(UUID.randomUUID()).isEmpty());
    }

    @Test
    void setRoleForNonexistentIdReturnsFalse() {
        assertFalse(repository.setRole(UUID.randomUUID(), Role.ADMIN));
    }
}
