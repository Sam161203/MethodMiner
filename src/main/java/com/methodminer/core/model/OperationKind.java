package com.methodminer.core.model;

/**
 * Coarse operation category shared across protocols.
 */
public enum OperationKind {
    UNKNOWN,
    QUERY,
    MUTATION,
    SUBSCRIPTION,
    METHOD
}
