package com.methodminer.core.events;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Lightweight, thread-safe in-memory {@link EventBus} implementation.
 */
public final class SimpleEventBus implements EventBus {
    private final ConcurrentHashMap<Class<?>, CopyOnWriteArrayList<EventListener<?>>> listenersByType = new ConcurrentHashMap<>();

    @Override
    public <T> void subscribe(Class<T> eventType, EventListener<? super T> listener) {
        Objects.requireNonNull(eventType, "eventType");
        Objects.requireNonNull(listener, "listener");

        CopyOnWriteArrayList<EventListener<?>> listeners = listenersByType.computeIfAbsent(eventType, ignored -> new CopyOnWriteArrayList<>());
        listeners.addIfAbsent(listener);
    }

    @Override
    public <T> void unsubscribe(Class<T> eventType, EventListener<? super T> listener) {
        Objects.requireNonNull(eventType, "eventType");
        Objects.requireNonNull(listener, "listener");

        CopyOnWriteArrayList<EventListener<?>> listeners = listenersByType.get(eventType);
        if (listeners == null) {
            return;
        }

        listeners.remove(listener);
        if (listeners.isEmpty()) {
            listenersByType.remove(eventType, listeners);
        }
    }

    @Override
    public <T> void publish(T event) {
        Objects.requireNonNull(event, "event");

        Object payload = event;
        for (var entry : listenersByType.entrySet()) {
            Class<?> subscribedType = entry.getKey();
            if (!subscribedType.isInstance(payload)) {
                continue;
            }

            for (EventListener<?> rawListener : entry.getValue()) {
                invoke(rawListener, payload);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void invoke(EventListener<?> rawListener, Object event) {
        try {
            ((EventListener<Object>) rawListener).onEvent(event);
        } catch (RuntimeException ignored) {
        }
    }
}
