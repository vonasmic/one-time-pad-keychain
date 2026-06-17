package fel.cvut.db;

public final class DatabaseConfig {
    private DatabaseConfig() {}

    public static String getDbUrl() {
        return requireEnv("DB_URL");
    }

    public static String getDbUsername() {
        return requireEnv("DB_USERNAME");
    }

    public static String getDbPassword() {
        return requireEnv("DB_PASSWORD");
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Required environment variable is not set: " + name);
        }
        return value.trim();
    }
}
