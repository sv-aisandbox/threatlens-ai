package ai.threatlens.backend.client;

/** Outcomes of calling the Python intelligence service. Messages are fixed text; upstream bodies are never kept. */
public final class UpstreamExceptions {

    private UpstreamExceptions() {}

    public static class NotFoundException extends RuntimeException {
        public NotFoundException() {
            super("not found");
        }
    }

    public static class ConflictException extends RuntimeException {
        public ConflictException() {
            super("conflict");
        }
    }

    /** The uploaded file cannot be used as a whole. `code` comes from a fixed set; `details` from our own vocabulary. */
    public static class InventoryRejectedException extends RuntimeException {
        private final String code;
        private final java.util.List<String> details;

        public InventoryRejectedException(String code, java.util.List<String> details) {
            super("inventory file rejected");
            this.code = code;
            this.details = details;
        }

        public String code() {
            return code;
        }

        public java.util.List<String> details() {
            return details;
        }
    }

    /** The intelligence service failed or is unreachable. {@code status} is 502 or 504. */
    public static class UpstreamException extends RuntimeException {
        private final int status;

        public UpstreamException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }
}
