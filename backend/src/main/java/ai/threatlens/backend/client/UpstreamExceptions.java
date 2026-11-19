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
