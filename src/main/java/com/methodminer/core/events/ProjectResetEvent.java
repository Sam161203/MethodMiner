package com.methodminer.core.events;

/**
 * Published when the project state has been reset (cleared).
 *
 * @param scope describes what was cleared: "project", "sessions", or "signals"
 */
public record ProjectResetEvent(String scope) {}
