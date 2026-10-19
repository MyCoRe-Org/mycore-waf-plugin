package org.mycore.waf.suspicion;

/**
 * Thrown by a fact that cannot be evaluated because the required data is not available, for
 * example because the GeoIP database has not been downloaded yet or the client uses a private IP
 * address. The whole rule containing the fact does not match in that case, even if the fact is
 * wrapped in {@code not}. Otherwise {@code <not><country .../></not>} would match every client
 * while the database is missing.
 */
public class UndeterminableFactException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message why the fact cannot be evaluated
     */
    public UndeterminableFactException(String message) {
        super(message, null, false, false);
    }

}
