package com.methodminer.core.events;

import com.methodminer.core.model.Observation;

import java.util.Objects;

/**
 * Emitted when a new normalized observation is ingested.
 */
public record ObservationEvent(Observation observation) {
    public ObservationEvent {
        observation = Objects.requireNonNull(observation, "observation");
    }
}
