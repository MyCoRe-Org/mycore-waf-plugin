package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A fact that is true if all contained facts are true. Fails closed if it contains no facts.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class AndFact extends Fact {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElements({
        @XmlElement(name = "and", type = AndFact.class),
        @XmlElement(name = "or", type = OrFact.class),
        @XmlElement(name = "not", type = NotFact.class),
        @XmlElement(name = "method", type = MethodFact.class),
        @XmlElement(name = "path", type = PathFact.class),
        @XmlElement(name = "parameter", type = ParameterFact.class),
        @XmlElement(name = "parameter-count", type = ParameterCountFact.class),
        @XmlElement(name = "header", type = HeaderFact.class),
        @XmlElement(name = "user-agent", type = UserAgentFact.class),
        @XmlElement(name = "remote-address", type = RemoteAddressFact.class),
        @XmlElement(name = "cookie", type = CookieFact.class),
        @XmlElement(name = "content-type", type = ContentTypeFact.class),
        @XmlElement(name = "query-string", type = QueryStringFact.class)
    })
    private List<Fact> facts = new ArrayList<>();

    @Override
    public boolean matches(HttpServletRequest request) {
        if (facts.isEmpty()) {
            LOGGER.warn("'and' fact without child facts never matches");
            return false;
        }
        return facts.stream().allMatch(fact -> fact.matches(request));
    }

    public List<Fact> getFacts() {
        return facts;
    }

    public void setFacts(List<Fact> facts) {
        this.facts = facts;
    }

}
