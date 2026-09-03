package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A fact that inverts its single contained fact. Fails closed if it contains no fact.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class NotFact extends Fact {

    private static final Logger LOGGER = LogManager.getLogger();

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

    @Override
    public boolean matches(HttpServletRequest request) {
        if (fact == null) {
            LOGGER.warn("'not' fact without child fact never matches");
            return false;
        }
        return !fact.matches(request);
    }

    public Fact getFact() {
        return fact;
    }

    public void setFact(Fact fact) {
        this.fact = fact;
    }

}
