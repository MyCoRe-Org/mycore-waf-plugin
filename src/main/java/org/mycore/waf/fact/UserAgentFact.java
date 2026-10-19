package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

/**
 * A fact that matches a Java regex against the {@code User-Agent} header of the request. Shortcut
 * for {@code <header name="User-Agent" .../>}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class UserAgentFact extends RegexFact {

    private static final String HEADER_NAME = "User-Agent";

    @Override
    protected String getValue(HttpServletRequest request) {
        return request.getHeader(HEADER_NAME);
    }

}
