package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

/**
 * A fact that matches a Java regex against the value of a request header. The header name is
 * looked up ignoring case, as defined by the servlet API.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class HeaderFact extends RegexFact {

    @XmlAttribute(required = true)
    private String name;

    @Override
    protected String getValue(HttpServletRequest request) {
        return request.getHeader(name);
    }

    public String getName() {
        return name;
    }

}
