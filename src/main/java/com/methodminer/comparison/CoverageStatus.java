package com.methodminer.comparison;

/**
 * Role coverage classification for an operation or parameter.
 */
public enum CoverageStatus {
    /** Observed only in ADMIN-labeled sessions. */
    ADMIN_ONLY,
    /** Observed only in LOW_PRIV-labeled sessions. */
    LOW_PRIV_ONLY,
    /** Observed in both ADMIN and LOW_PRIV sessions. */
    BOTH,
    /** Observed only in sessions with no role label. */
    UNLABELED,
    /** No attributable role could be determined. */
    UNKNOWN
}
