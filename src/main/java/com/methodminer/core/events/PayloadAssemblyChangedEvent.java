package com.methodminer.core.events;

import com.methodminer.payload.PayloadAssemblyResult;

import java.util.Objects;

/**
 * Emitted when payload candidates have been reassembled.
 */
public record PayloadAssemblyChangedEvent(PayloadAssemblyResult result) {
    public PayloadAssemblyChangedEvent {
        result = Objects.requireNonNull(result, "result");
    }
}
