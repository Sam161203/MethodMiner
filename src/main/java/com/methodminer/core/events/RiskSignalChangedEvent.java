package com.methodminer.core.events;

import com.methodminer.risk.RiskSignalResult;

import java.util.Objects;

/**
 * Emitted when risk signals have been regenerated.
 */
public record RiskSignalChangedEvent(RiskSignalResult result) {
    public RiskSignalChangedEvent {
        result = Objects.requireNonNull(result, "result");
    }
}
