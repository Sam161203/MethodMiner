package com.methodminer.session;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable, normalized summary of authentication material observed in a single HTTP exchange.
 *
 * <p>Contains only safe summaries and hashes — never raw secrets.
 *
 * @param host             Target host the request was sent to
 * @param authMechanism    Detected mechanism (e.g. "Bearer", "Basic", "Cookie", "API-Key", "JSON-RPC-credentials")
 * @param tokenHash        SHA-256 prefix hash of the primary auth token (first 16 hex chars)
 * @param username         Detected username (may be empty)
 * @param database         Detected tenant/database (may be empty)
 * @param cookieNames      Set of cookie names observed (not values)
 * @param authHeaderNames  Set of auth-related header names observed
 * @param metadata         Additional protocol-specific key-value pairs
 */
public record SessionFingerprint(
        String host,
        String authMechanism,
        String tokenHash,
        String username,
        String database,
        Set<String> cookieNames,
        Set<String> authHeaderNames,
        Map<String, String> metadata
) {
    /** An empty fingerprint indicating no authentication was detected. */
    public static final SessionFingerprint EMPTY = new SessionFingerprint(
            "", "", "", "", "", Set.of(), Set.of(), Map.of());

    public SessionFingerprint {
        host = Objects.requireNonNullElse(host, "");
        authMechanism = Objects.requireNonNullElse(authMechanism, "");
        tokenHash = Objects.requireNonNullElse(tokenHash, "");
        username = Objects.requireNonNullElse(username, "");
        database = Objects.requireNonNullElse(database, "");
        cookieNames = Set.copyOf(Objects.requireNonNullElse(cookieNames, Set.of()));
        authHeaderNames = Set.copyOf(Objects.requireNonNullElse(authHeaderNames, Set.of()));
        metadata = Map.copyOf(Objects.requireNonNullElse(metadata, Map.of()));
    }

    /** Returns true if no authentication material was detected. */
    public boolean isEmpty() {
        return tokenHash.isBlank() && cookieNames.isEmpty() && authHeaderNames.isEmpty()
                && username.isBlank() && database.isBlank();
    }
}
