package com.methodminer.risk;

/**
 * Confidence level indicating the strength of evidence behind a risk signal.
 */
public enum RiskConfidence {
    /** Multiple strong indicators converge. */
    HIGH,
    /** Moderate indicators present. */
    MEDIUM,
    /** Single or weak indicator. */
    LOW
}
