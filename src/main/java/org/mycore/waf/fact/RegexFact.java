package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Base class for facts that match a Java regex against a single value taken from the request. The
 * regex must match the whole value ({@link java.util.regex.Matcher#matches()}), not just a part of
 * it. An invalid regex is reported once and makes the fact never match.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class RegexFact extends Fact {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final Pattern NEVER_MATCHES = Pattern.compile("(?!)");

    @XmlAttribute(required = true)
    private String pattern;

    private transient Pattern compiledPattern;

    @Override
    public boolean matches(HttpServletRequest request) {
        Pattern p = getCompiledPattern();
        String value = getValue(request);
        return p != null && value != null && p.matcher(value).matches();
    }

    /**
     * Returns the request value this fact is matched against, or null if the value is not present in
     * the request.
     *
     * @param request the incoming HTTP request
     * @return the value to match
     */
    protected abstract String getValue(HttpServletRequest request);

    protected Pattern getCompiledPattern() {
        if (compiledPattern == null) {
            try {
                compiledPattern = Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                LOGGER.error("Invalid regular expression '{}' in fact {}: {}", pattern,
                    getClass().getSimpleName(), e.getMessage());
                compiledPattern = NEVER_MATCHES;
            }
        }
        return compiledPattern;
    }

}
