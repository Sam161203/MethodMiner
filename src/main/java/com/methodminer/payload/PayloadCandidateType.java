package com.methodminer.payload;

/**
 * Classification of payload candidate types.
 */
public enum PayloadCandidateType {
    /** Replay an ADMIN-only operation with LOW_PRIV credentials. */
    ROLE_REPLAY,
    /** Inject admin-only parameters into a LOW_PRIV request. */
    PARAMETER_INJECTION,
    /** Replay a GraphQL mutation with LOW_PRIV credentials. */
    GRAPHQL_MUTATION_REPLAY,
    /** Chain a privileged operation inside a batch/multi-call request. */
    BATCH_CHAIN_REPLAY,
    /** Enumerate entity IDs to test for IDOR/BOLA. */
    ENUMERATION_REPLAY,
    /** Template from an ADMIN observation for manual credential substitution. */
    ADMIN_TEMPLATE
}
