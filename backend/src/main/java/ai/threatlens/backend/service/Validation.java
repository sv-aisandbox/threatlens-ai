package ai.threatlens.backend.service;

import java.util.Set;
import java.util.regex.Pattern;

/** Input rules shared by controllers (declarative) and services (defense in depth). */
public final class Validation {

    public static final String CVE_REGEX = "^CVE-\\d{4}-\\d{4,}$";
    public static final String ENVIRONMENT_REGEX = "^(production|staging|development)$";
    public static final String SOURCE_REGEX = "^(nvd|kev)$";

    private static final Pattern CVE = Pattern.compile(CVE_REGEX);
    private static final Set<String> ENVIRONMENTS = Set.of("production", "staging", "development");
    private static final Set<String> SOURCES = Set.of("nvd", "kev");

    private Validation() {}

    public static String cveId(String value) {
        if (value == null || value.length() > 40 || !CVE.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid CVE id");
        }
        return value;
    }

    public static String environmentOrNull(String value) {
        if (value != null && !ENVIRONMENTS.contains(value)) {
            throw new IllegalArgumentException("invalid environment");
        }
        return value;
    }

    public static String sourceId(String value) {
        if (value == null || !SOURCES.contains(value)) {
            throw new IllegalArgumentException("invalid source");
        }
        return value;
    }
}
