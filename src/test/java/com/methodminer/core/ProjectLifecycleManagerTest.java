package com.methodminer.core;

import com.methodminer.core.events.ProjectResetEvent;
import com.methodminer.core.events.SimpleEventBus;
import com.methodminer.core.events.SurfaceChangedEvent;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.Role;
import com.methodminer.core.model.SessionProfile;
import com.methodminer.core.repository.InMemorySurfaceRepository;
import com.methodminer.session.InMemorySessionRepository;
import com.methodminer.session.SessionFingerprint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ProjectLifecycleManager} covering reset, clear, and refresh behavior.
 */
class ProjectLifecycleManagerTest {

    private InMemorySurfaceRepository surfaceRepo;
    private InMemorySessionRepository sessionRepo;
    private SimpleEventBus eventBus;
    private ProjectLifecycleManager lifecycle;

    @BeforeEach
    void setUp() {
        surfaceRepo = new InMemorySurfaceRepository("test-project");
        sessionRepo = new InMemorySessionRepository();
        eventBus = new SimpleEventBus();
        lifecycle = new ProjectLifecycleManager(surfaceRepo, sessionRepo, eventBus);
    }

    // ---- Clear Project Tests ------------------------------------------------

    @Test
    void clearProjectResetsAllRepositories() {
        // Add some session data
        SessionFingerprint fp = new SessionFingerprint("host.com", "Bearer", "hash1",
                "admin@test.com", "", Set.of(), Set.of("Authorization"), Map.of());
        SessionProfile profile = sessionRepo.upsert(fp, Instant.now());
        sessionRepo.setRole(profile.id(), Role.ADMIN);

        assertFalse(sessionRepo.snapshot().isEmpty());

        lifecycle.clearProject();

        assertTrue(sessionRepo.snapshot().isEmpty());
    }

    @Test
    void clearProjectResetsSurfaceToEmpty() {
        ApiSurface before = surfaceRepo.snapshot();
        assertNotNull(before);

        lifecycle.clearProject();

        ApiSurface after = surfaceRepo.snapshot();
        assertTrue(after.services().isEmpty());
        assertTrue(after.observations().isEmpty());
    }

    @Test
    void clearProjectPublishesResetEvent() {
        List<ProjectResetEvent> events = new ArrayList<>();
        eventBus.subscribe(ProjectResetEvent.class, events::add);

        lifecycle.clearProject();

        assertEquals(1, events.size());
        assertEquals("project", events.get(0).scope());
    }

    @Test
    void clearProjectPublishesSurfaceChangedEvent() {
        List<SurfaceChangedEvent> events = new ArrayList<>();
        eventBus.subscribe(SurfaceChangedEvent.class, events::add);

        lifecycle.clearProject();

        assertEquals(1, events.size());
        assertNotNull(events.get(0).surface());
    }

    // ---- Clear Sessions Tests -----------------------------------------------

    @Test
    void clearSessionsRemovesAllProfiles() {
        SessionFingerprint fp = new SessionFingerprint("host.com", "Bearer", "hash1",
                "user@test.com", "", Set.of(), Set.of(), Map.of());
        sessionRepo.upsert(fp, Instant.now());

        assertFalse(sessionRepo.snapshot().isEmpty());

        lifecycle.clearSessions();

        assertTrue(sessionRepo.snapshot().isEmpty());
    }

    @Test
    void clearSessionsPublishesResetEvent() {
        List<ProjectResetEvent> events = new ArrayList<>();
        eventBus.subscribe(ProjectResetEvent.class, events::add);

        lifecycle.clearSessions();

        assertEquals(1, events.size());
        assertEquals("sessions", events.get(0).scope());
    }

    @Test
    void clearSessionsDoesNotClearSurface() {
        ApiSurface before = surfaceRepo.snapshot();

        lifecycle.clearSessions();

        ApiSurface after = surfaceRepo.snapshot();
        assertEquals(before.id(), after.id()); // Same surface
    }

    // ---- Refresh Analysis Tests ---------------------------------------------

    @Test
    void refreshAnalysisPublishesSurfaceChanged() {
        List<SurfaceChangedEvent> events = new ArrayList<>();
        eventBus.subscribe(SurfaceChangedEvent.class, events::add);

        lifecycle.refreshAnalysis();

        assertEquals(1, events.size());
        assertNotNull(events.get(0).surface());
    }

    @Test
    void refreshAnalysisPreservesData() {
        SessionFingerprint fp = new SessionFingerprint("host.com", "Bearer", "hash1",
                "admin@test.com", "", Set.of(), Set.of("Authorization"), Map.of());
        sessionRepo.upsert(fp, Instant.now());

        lifecycle.refreshAnalysis();

        // Sessions should still exist
        assertEquals(1, sessionRepo.snapshot().size());
    }

    // ---- Repository Clear Tests ---------------------------------------------

    @Test
    void sessionRepositoryClearRemovesAll() {
        SessionFingerprint fp1 = new SessionFingerprint("host1.com", "Bearer", "hash1",
                "user1@test.com", "", Set.of(), Set.of(), Map.of());
        SessionFingerprint fp2 = new SessionFingerprint("host2.com", "Token", "hash2",
                "user2@test.com", "", Set.of(), Set.of(), Map.of());
        sessionRepo.upsert(fp1, Instant.now());
        sessionRepo.upsert(fp2, Instant.now());

        assertEquals(2, sessionRepo.snapshot().size());

        sessionRepo.clear();

        assertTrue(sessionRepo.snapshot().isEmpty());
    }

    @Test
    void surfaceRepositoryClearResetsToEmpty() {
        surfaceRepo.clear();

        ApiSurface surface = surfaceRepo.snapshot();
        assertTrue(surface.services().isEmpty());
        assertTrue(surface.observations().isEmpty());
        assertEquals("test-project", surface.projectName());
    }

    @Test
    void clearSessionsThenUpsertWorks() {
        SessionFingerprint fp = new SessionFingerprint("host.com", "Bearer", "hash1",
                "admin@test.com", "", Set.of(), Set.of(), Map.of());
        sessionRepo.upsert(fp, Instant.now());
        sessionRepo.clear();
        assertTrue(sessionRepo.snapshot().isEmpty());

        // Can add sessions again after clear
        SessionProfile sp = sessionRepo.upsert(fp, Instant.now());
        assertNotNull(sp);
        assertEquals(1, sessionRepo.snapshot().size());
    }

    // ---- Null Session Repository Tests --------------------------------------

    @Test
    void clearProjectWithNullSessionRepoDoesNotThrow() {
        ProjectLifecycleManager lcm = new ProjectLifecycleManager(surfaceRepo, null, eventBus);
        assertDoesNotThrow(lcm::clearProject);
    }

    @Test
    void clearSessionsWithNullSessionRepoDoesNotThrow() {
        ProjectLifecycleManager lcm = new ProjectLifecycleManager(surfaceRepo, null, eventBus);
        assertDoesNotThrow(lcm::clearSessions);
    }
}
