public enum RoleType {
    ADMIN,
    LOW_PRIV,
    MIXED,
    UNKNOWN;

    public String displayName() {
        return switch (this) {
            case ADMIN -> "ADMIN";
            case LOW_PRIV -> "LOW_PRIV";
            case MIXED -> "MIXED (ADMIN + LOW_PRIV)";
            case UNKNOWN -> "UNKNOWN";
        };
    }
}
