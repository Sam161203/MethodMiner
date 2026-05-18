package com.methodminer.core.events;

/**
 * Type-safe event listener.
 */
@FunctionalInterface
public interface EventListener<T> {
    void onEvent(T event);
}
