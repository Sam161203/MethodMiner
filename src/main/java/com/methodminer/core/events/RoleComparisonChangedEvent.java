package com.methodminer.core.events;

import com.methodminer.comparison.RoleComparisonResult;

import java.util.Objects;

/**
 * Emitted when the role comparison analysis has been recomputed.
 */
public record RoleComparisonChangedEvent(RoleComparisonResult result) {
    public RoleComparisonChangedEvent {
        result = Objects.requireNonNull(result, "result");
    }
}
