package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.List;

/**
 * A fact that matches a Java regex against a field of the client information, for example
 * {@code <value field="timezone" pattern="UTC|Etc/.*"/>}. Numbers and booleans are matched by
 * their string representation, array fields like {@code languages} are matched element by element.
 * A missing field never matches, use {@link MissingFact} to detect it.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ValueFact extends PatternFact {

    @XmlAttribute(required = true)
    private String field;

    @Override
    protected List<String> getValues(ClientInformation information) {
        return information.getValues(field);
    }

}
