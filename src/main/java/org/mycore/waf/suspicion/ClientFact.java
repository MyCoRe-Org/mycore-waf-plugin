package org.mycore.waf.suspicion;

import java.util.ArrayList;
import java.util.List;

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

    /**
     * Evaluates all facts, without short circuit. If any fact cannot be evaluated, the exception is
     * rethrown after all facts were evaluated, so that the result does not depend on the order of
     * the facts.
     *
     * @param facts the facts to evaluate
     * @param information the client information and the request that submitted it
     * @return the result of every fact, in order
     * @throws UndeterminableFactException if any fact cannot be evaluated
     */
    static List<Boolean> evaluateAll(List<ClientFact> facts, ClientInformation information) {
        List<Boolean> results = new ArrayList<>();
        UndeterminableFactException undeterminable = null;
        for (ClientFact fact : facts) {
            try {
                results.add(fact.matches(information));
            } catch (UndeterminableFactException e) {
                if (undeterminable == null) {
                    undeterminable = e;
                }
            }
        }
        if (undeterminable != null) {
            throw undeterminable;
        }
        return results;
    }

}
