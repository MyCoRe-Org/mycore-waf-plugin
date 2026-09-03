package org.mycore.waf.fact;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.regex.Pattern;

/**
 * A fact that checks a cookie of the request. Without a {@code pattern} the fact is true if a
 * cookie with the given name exists. With a {@code pattern} it is true if the cookie value matches
 * the regex.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class CookieFact extends Fact {

    @XmlAttribute(required = true)
    private String name;

    @XmlAttribute
    private String pattern;

    private transient volatile Pattern compiledPattern;

    @Override
    public boolean matches(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return false;
        }
        for (Cookie cookie : cookies) {
            if (!name.equals(cookie.getName())) {
                continue;
            }
            if (pattern == null) {
                return true;
            }
            Pattern p = getCompiledPattern();
            if (p != null && cookie.getValue() != null && p.matcher(cookie.getValue()).matches()) {
                return true;
            }
        }
        return false;
    }

    private Pattern getCompiledPattern() {
        if (compiledPattern == null && pattern != null) {
            compiledPattern = RegexFact.compilePattern(pattern, "cookie fact");
        }
        return compiledPattern;
    }

}
