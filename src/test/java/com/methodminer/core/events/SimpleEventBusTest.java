package com.methodminer.core.events;

import com.methodminer.core.model.Observation;
import com.methodminer.protocol.ProtocolKind;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SimpleEventBusTest {

    @Test
    void deliversPublishedEventsToSubscribers() {
        SimpleEventBus bus = new SimpleEventBus();
        List<ObservationEvent> received = new CopyOnWriteArrayList<>();

        bus.subscribe(ObservationEvent.class, event -> received.add(event));
        ObservationEvent published = new ObservationEvent(sampleObservation());

        bus.publish(published);

        assertEquals(1, received.size());
        assertEquals(published, received.get(0));
    }

    @Test
    void unsubscribeStopsDelivery() {
        SimpleEventBus bus = new SimpleEventBus();
        List<ObservationEvent> received = new CopyOnWriteArrayList<>();

        EventListener<ObservationEvent> listener = event -> received.add(event);
        bus.subscribe(ObservationEvent.class, listener);
        bus.unsubscribe(ObservationEvent.class, listener);

        bus.publish(new ObservationEvent(sampleObservation()));

        assertEquals(0, received.size());
    }

    @Test
    void listenerExceptionsDoNotBreakPublish() {
        SimpleEventBus bus = new SimpleEventBus();
        List<ObservationEvent> received = new CopyOnWriteArrayList<>();

        bus.subscribe(ObservationEvent.class, event -> {
            throw new RuntimeException("boom");
        });
        bus.subscribe(ObservationEvent.class, event -> received.add(event));

        assertDoesNotThrow(() -> bus.publish(new ObservationEvent(sampleObservation())));
        assertEquals(1, received.size());
    }

    private static Observation sampleObservation() {
        return new Observation(
                UUID.randomUUID(),
                ProtocolKind.JSON_RPC,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                Optional.empty(),
                Instant.now(),
                Map.of("k", "v"),
                Optional.of("req"),
                Optional.of("res")
        );
    }
}
