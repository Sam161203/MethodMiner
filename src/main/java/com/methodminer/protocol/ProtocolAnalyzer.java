package com.methodminer.protocol;

import com.methodminer.core.model.Observation;

import java.util.List;

/**
 * Normalizes protocol-specific exchanges into protocol-agnostic {@link Observation} facts.
 */
public interface ProtocolAnalyzer {

    /**
     * Convert a detected exchange into one or more normalized observations.
     */
    List<Observation> normalize(HttpExchange exchange, DetectionResult detection);
}
