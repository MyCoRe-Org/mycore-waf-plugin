package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A single suspicion rule. Contains exactly one fact element, which may be a combinator like
 * {@code and} that nests further facts. The required {@code name} attribute is logged as the reason
 * why a client was considered suspicious. If a fact of the rule cannot be evaluated because data is
 * missing (see {@link UndeterminableFactException}), the rule does not match.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class SuspicionRule {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlAttribute(required = true)
    private String name;

    @XmlElements({
        @XmlElement(name = "and", type = AndFact.class, required = true),
        @XmlElement(name = "or", type = OrFact.class, required = true),
        @XmlElement(name = "not", type = NotFact.class, required = true),
        @XmlElement(name = "value", type = ValueFact.class, required = true),
        @XmlElement(name = "missing", type = MissingFact.class, required = true),
        @XmlElement(name = "number", type = NumberFact.class, required = true),
        @XmlElement(name = "count", type = CountFact.class, required = true),
        @XmlElement(name = "header", type = HeaderFact.class, required = true),
        @XmlElement(name = "same-as-header", type = SameAsHeaderFact.class, required = true),
        @XmlElement(name = "timezone-offset-mismatch", type = TimezoneOffsetMismatchFact.class, required = true),
        @XmlElement(name = "remote-address", type = RemoteAddressFact.class, required = true),
        @XmlElement(name = "redirect-url", type = RedirectURLFact.class, required = true),
        @XmlElement(name = "country", type = CountryFact.class, required = true),
        @XmlElement(name = "asn", type = ASNFact.class, required = true)
    })
    private ClientFact fact;

    /**
     * Evaluates the fact of this rule against the given client information.
     *
     * @param information the client information and the request that submitted it
     * @return true if the fact of this rule matches, false otherwise
     */
    public boolean matches(ClientInformation information) {
        if (fact == null) {
            return false;
        }
        try {
            return fact.matches(information);
        } catch (UndeterminableFactException e) {
            LOGGER.debug("Suspicion rule '{}' cannot be evaluated: {}", name, e.getMessage());
            return false;
        }
    }

    void validate() {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Suspicion rule without name");
        }
        if (fact == null) {
            throw new IllegalArgumentException("Suspicion rule '" + name + "' has no fact");
        }
        fact.validate();
    }

    public String getName() {
        return name;
    }

}
