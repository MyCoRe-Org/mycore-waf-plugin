package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

/**
 * A fact that matches a Java regex against the raw query string of the request, including
 * parameter order and encoded delimiters. Never matches if the request has no query string.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class QueryStringFact extends RegexFact {

    @Override
    protected String getValue(HttpServletRequest request) {
        return request.getQueryString();
    }

}
