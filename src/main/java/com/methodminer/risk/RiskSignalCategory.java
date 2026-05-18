package com.methodminer.risk;

/**
 * Classification of risk signal categories.
 */
public enum RiskSignalCategory {
    /** Operation observed only in ADMIN sessions. */
    PRIVILEGED_OPERATION,
    /** Sensitive operation observed in both ADMIN and LOW_PRIV sessions. */
    SHARED_SENSITIVE_OPERATION,
    /** Parameters differ between ADMIN and LOW_PRIV for the same operation. */
    PARAMETER_EXPOSURE_DIFFERENCE,
    /** Mutation operation observed only in ADMIN sessions. */
    ADMIN_ONLY_MUTATION,
    /** Delete/Remove operation observed only in ADMIN sessions. */
    ADMIN_ONLY_DELETE,
    /** GraphQL mutation observed only in ADMIN sessions. */
    GRAPHQL_MUTATION_PRIVILEGE,
    /** JSON-RPC batch/multi-call candidate for chaining. */
    BATCH_CHAIN_CANDIDATE,
    /** Get/Search/List pattern suitable for enumeration testing. */
    ENUMERATION_CANDIDATE
}
