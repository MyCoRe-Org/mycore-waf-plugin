package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;

/**
 * A single fact (predicate) that is evaluated against an incoming HTTP request. A fact is either a
 * combinator ({@link AndFact}, {@link OrFact}, {@link NotFact}) that contains other facts, or a
 * leaf fact that checks one property of the request, for example its method, path or a header.
 */
public abstract class Fact {

    void validate() {
    }

    /**
     * Evaluates this fact against the given request.
     *
     * @param request the incoming HTTP request
     * @return true if the fact holds for the request, false otherwise
     */
    public abstract boolean matches(HttpServletRequest request);

}
