package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.Collections;
import java.util.List;

/**
 * A fact that matches a Java regex against a header of the challenge solution request, for example
 * {@code <header name="Accept-Language" pattern="en.*"/>}. A missing header never matches, so
 * {@code <not><header name="Accept-Language" pattern=".+"/></not>} detects a missing header.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class HeaderFact extends PatternFact {

    @XmlAttribute(required = true)
    private String name;

    @Override
    protected List<String> getValues(ClientInformation information) {
        return Collections.list(information.request().getHeaders(name));
    }

}
