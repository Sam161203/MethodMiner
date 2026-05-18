package com.methodminer.protocol.jsonrpc;

import java.util.Objects;

/**
 * Minimal namespace helper for JSON-RPC method names (e.g. {@code user.getProfile}).
 */
public final class JsonRpcMethodName {
    private JsonRpcMethodName() {
    }

    public static String namespaceOf(String methodName) {
        String normalized = normalize(methodName);
        if (normalized.isBlank()) {
            return "";
        }

        int dot = normalized.indexOf('.');
        int slash = normalized.indexOf('/');
        int separator = chooseSeparatorIndex(dot, slash);
        if (separator <= 0) {
            return "";
        }
        return normalized.substring(0, separator);
    }

    public static String simpleNameOf(String methodName) {
        String normalized = normalize(methodName);
        if (normalized.isBlank()) {
            return "";
        }

        int dot = normalized.lastIndexOf('.');
        int slash = normalized.lastIndexOf('/');
        int separator = Math.max(dot, slash);
        if (separator < 0 || separator >= normalized.length() - 1) {
            return normalized;
        }
        return normalized.substring(separator + 1);
    }

    private static int chooseSeparatorIndex(int dot, int slash) {
        if (dot < 0) {
            return slash;
        }
        if (slash < 0) {
            return dot;
        }
        return Math.min(dot, slash);
    }

    private static String normalize(String methodName) {
        return Objects.requireNonNullElse(methodName, "").trim();
    }
}
