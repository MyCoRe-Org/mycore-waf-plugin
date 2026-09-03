package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import org.mycore.waf.WAFAllowListChecker;

/**
 * A fact that matches a Java regex against the request path relative to the application base URL,
 * that is without the context path, as used by {@code MCR.WAF.AllowedPaths}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class PathFact extends RegexFact {

    @Override
    protected String getValue(HttpServletRequest request) {
        return WAFAllowListChecker.getApplicationRelativePath(request);
    }

}
