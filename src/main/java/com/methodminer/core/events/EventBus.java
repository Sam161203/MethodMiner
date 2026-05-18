package com.methodminer.core.events;

/**
 * Minimal, type-safe publish/subscribe event bus.
 */
public interface EventBus {

    <T> void subscribe(Class<T> eventType, EventListener<? super T> listener);

    <T> void unsubscribe(Class<T> eventType, EventListener<? super T> listener);

    <T> void publish(T event);
}
