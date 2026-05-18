package com.methodminer.core;

import com.methodminer.core.events.EventBus;
import com.methodminer.core.events.ProjectResetEvent;
import com.methodminer.core.events.SurfaceChangedEvent;
import com.methodminer.core.repository.SurfaceRepository;
import com.methodminer.session.SessionRepository;

import java.util.Objects;

/**
 * Manages project data lifecycle — clearing, resetting, and coordinating refresh.
 *
 * <p>All reset operations publish events so the UI and downstream engines react.
 */
public final class ProjectLifecycleManager {

    private final SurfaceRepository surfaceRepository;
    private final SessionRepository sessionRepository;
    private final EventBus eventBus;

    public ProjectLifecycleManager(SurfaceRepository surfaceRepository,
                                    SessionRepository sessionRepository,
                                    EventBus eventBus) {
        this.surfaceRepository = Objects.requireNonNull(surfaceRepository, "surfaceRepository");
        this.sessionRepository = sessionRepository; // may be null in tests
        this.eventBus = Objects.requireNonNull(eventBus, "eventBus");
    }

    /**
     * Clear all project data — surface, sessions, and all derived analysis.
     * Publishes events to trigger full UI refresh.
     */
    public void clearProject() {
        surfaceRepository.clear();
        if (sessionRepository != null) {
            sessionRepository.clear();
        }
        eventBus.publish(new ProjectResetEvent("project"));
        eventBus.publish(new SurfaceChangedEvent(surfaceRepository.snapshot()));
    }

    /**
     * Clear only session profiles and role labels.
     * Preserves captured observations and API surface.
     */
    public void clearSessions() {
        if (sessionRepository != null) {
            sessionRepository.clear();
        }
        eventBus.publish(new ProjectResetEvent("sessions"));
    }

    /**
     * Trigger analysis refresh without clearing captured data.
     * Publishes a SurfaceChangedEvent so downstream engines recompute.
     */
    public void refreshAnalysis() {
        eventBus.publish(new SurfaceChangedEvent(surfaceRepository.snapshot()));
    }
}
