package com.methodminer.core.model;

/**
 * Structural kind of an inferred data type.
 */
public enum DataTypeKind {
    UNKNOWN,
    SCALAR,
    OBJECT,
    ARRAY,
    ENUM,
    UNION,
    INPUT_OBJECT
}
