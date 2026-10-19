package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

/**
 * A fact that checks the HTTP method of the request. The {@code value} attribute contains a comma
 * separated list of accepted methods, compared ignoring case.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class MethodFact extends Fact {

    @XmlAttribute(name = "value", required = true)
    private String value;

    @Override
    public boolean matches(HttpServletRequest request) {
        String method = request.getMethod();
        for (String accepted : value.split(",")) {
            if (method.equalsIgnoreCase(accepted.trim())) {
                return true;
            }
        }
        return false;
    }

}
