package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

/**
 * A fact that matches a Java regex against the content type of the request body, as announced by
 * the {@code Content-Type} header. Never matches if the request has no content type.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ContentTypeFact extends RegexFact {

    @Override
    protected String getValue(HttpServletRequest request) {
        return request.getContentType();
    }

}
