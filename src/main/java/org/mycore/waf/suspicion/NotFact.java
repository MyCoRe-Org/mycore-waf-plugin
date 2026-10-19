package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;

/**
 * A fact that inverts its single contained fact. Never matches if it contains no fact.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class NotFact extends ClientFact {

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

    @Override
    public boolean matches(ClientInformation information) {
        return fact != null && !fact.matches(information);
    }

    @Override
    void validate() {
        if (fact == null) {
            throw new IllegalArgumentException("'not' fact has no child fact");
        }
        fact.validate();
    }

}
