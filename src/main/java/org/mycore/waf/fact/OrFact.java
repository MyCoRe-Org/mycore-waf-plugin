package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

/**
 * A fact that is true if at least one contained fact is true. Never matches if it contains no
 * facts.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class OrFact extends Fact {

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
        return facts.stream().anyMatch(fact -> fact.matches(request));
    }

    public List<Fact> getFacts() {
        return facts;
    }

    public void setFacts(List<Fact> facts) {
        this.facts = facts;
    }

}
