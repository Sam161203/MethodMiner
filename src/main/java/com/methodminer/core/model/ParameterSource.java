package com.methodminer.core.model;

/**
 * Where a parameter is supplied from, independent of protocol.
 */
public enum ParameterSource {
    UNKNOWN,
    PATH,
    QUERY,
    HEADER,
    COOKIE,
    BODY,
    GRAPHQL_VARIABLE,
    JSON_RPC_PARAM
}
