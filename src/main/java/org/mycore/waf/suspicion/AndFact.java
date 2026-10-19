package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A fact that is true if all contained facts are true. Never matches if it contains no facts.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class AndFact extends ClientFact {

    @XmlElements({
        @XmlElement(name = "and", type = AndFact.class),
        @XmlElement(name = "or", type = OrFact.class),
        @XmlElement(name = "not", type = NotFact.class),
        @XmlElement(name = "value", type = ValueFact.class),
        @XmlElement(name = "missing", type = MissingFact.class),
        @XmlElement(name = "number", type = NumberFact.class),
        @XmlElement(name = "count", type = CountFact.class),
        @XmlElement(name = "header", type = HeaderFact.class),
        @XmlElement(name = "same-as-header", type = SameAsHeaderFact.class),
        @XmlElement(name = "timezone-offset-mismatch", type = TimezoneOffsetMismatchFact.class),
        @XmlElement(name = "remote-address", type = RemoteAddressFact.class),
        @XmlElement(name = "redirect-url", type = RedirectURLFact.class),
        @XmlElement(name = "country", type = CountryFact.class),
        @XmlElement(name = "asn", type = ASNFact.class)
    })
    private List<ClientFact> facts = new ArrayList<>();

    @Override
    public boolean matches(ClientInformation information) {
        return !facts.isEmpty() && evaluateAll(facts, information).stream().allMatch(Boolean::booleanValue);
    }

    @Override
    void collectGeoIPDatabases(Set<String> databases) {
        facts.forEach(fact -> fact.collectGeoIPDatabases(databases));
    }

    @Override
    void validate() {
        if (facts.isEmpty()) {
            throw new IllegalArgumentException("'and' fact has no child facts");
        }
        facts.forEach(ClientFact::validate);
    }

}
