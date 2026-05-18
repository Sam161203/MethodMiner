package com.methodminer.payload;

import java.util.Objects;

/**
 * A variable placeholder within a payload template.
 *
 * @param name         variable name (e.g. "sessionId", "deviceId")
 * @param placeholder  placeholder text in the template (e.g. "&lt;LOW_PRIV_SESSION_ID&gt;")
 * @param description  human-readable description of what to substitute
 * @param sourceRole   role from which the original value was observed (e.g. "ADMIN")
 * @param currentValue current resolved value, if available (empty string if placeholder)
 */
public record PayloadVariable(
        String name,
        String placeholder,
        String description,
        String sourceRole,
        String currentValue
) {
    public PayloadVariable {
        name = Objects.requireNonNull(name, "name");
        placeholder = Objects.requireNonNullElse(placeholder, "");
        description = Objects.requireNonNullElse(description, "");
        sourceRole = Objects.requireNonNullElse(sourceRole, "");
        currentValue = Objects.requireNonNullElse(currentValue, "");
    }
}
