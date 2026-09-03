package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A single allow rule. Contains exactly one fact element, which may be a combinator like
 * {@code and} that nests further facts. The optional {@code name} attribute is only used for
 * logging. A rule without a fact never matches.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class AllowRule {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlAttribute
    private String name;

    @XmlElements({
        @XmlElement(name = "and", type = AndFact.class, required = true),
        @XmlElement(name = "or", type = OrFact.class, required = true),
        @XmlElement(name = "not", type = NotFact.class, required = true),
        @XmlElement(name = "method", type = MethodFact.class, required = true),
        @XmlElement(name = "path", type = PathFact.class, required = true),
        @XmlElement(name = "parameter", type = ParameterFact.class, required = true),
        @XmlElement(name = "parameter-count", type = ParameterCountFact.class, required = true),
        @XmlElement(name = "header", type = HeaderFact.class, required = true),
        @XmlElement(name = "user-agent", type = UserAgentFact.class, required = true),
        @XmlElement(name = "remote-address", type = RemoteAddressFact.class, required = true),
        @XmlElement(name = "cookie", type = CookieFact.class, required = true),
        @XmlElement(name = "content-type", type = ContentTypeFact.class, required = true),
        @XmlElement(name = "query-string", type = QueryStringFact.class, required = true)
    })
    private Fact fact;

    /**
     * Evaluates the fact of this rule against the given request.
     *
     * @param request the incoming HTTP request
     * @return true if the fact of this rule matches, false otherwise
     */
    public boolean matches(HttpServletRequest request) {
        if (fact == null) {
            LOGGER.warn("Allow rule '{}' without fact never matches", name);
            return false;
        }
        boolean result = fact.matches(request);
        if (result) {
            String queryString = request.getQueryString();
            LOGGER.debug("Request {} {}{} matches allow rule '{}'", request.getMethod(),
                request.getRequestURI(), queryString == null ? "" : "?" + queryString, name);
        }
        return result;
    }

    void validate() {
        if (fact == null) {
            throw new IllegalArgumentException("Allow rule '" + name + "' has no fact");
        }
        fact.validate();
    }

    public String getName() {
        return name;
    }

    public Fact getFact() {
        return fact;
    }

    public void setFact(Fact fact) {
        this.fact = fact;
    }

}
