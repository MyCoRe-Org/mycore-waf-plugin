package org.mycore.waf.suspicion;

/**
 * A single fact (predicate) that is evaluated against the client information of a solved
 * challenge. A fact is either a combinator ({@link AndFact}, {@link OrFact}, {@link NotFact}) that
 * contains other facts, or a leaf fact that checks one property of the client information or the
 * request.
 */
public abstract class ClientFact {

    void validate() {
    }

    /**
     * Evaluates this fact against the given client information.
     *
     * @param information the client information and the request that submitted it
     * @return true if the fact holds, false otherwise
     */
    public abstract boolean matches(ClientInformation information);

}
