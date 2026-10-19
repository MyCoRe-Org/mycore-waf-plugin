package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

/**
 * A fact that checks a numeric field of the client information against an inclusive range, for
 * example {@code <number field="hardwareConcurrency" min="129"/>}. A missing or non numeric field
 * never matches.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class NumberFact extends RangeFact {

    @XmlAttribute(required = true)
    private String field;

    @Override
    protected Double getNumber(ClientInformation information) {
        return information.getNumber(field);
    }

}
