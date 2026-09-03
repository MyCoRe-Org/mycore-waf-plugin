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

    private transient volatile Pattern compiledPattern;

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

    /**
     * Compiles a regex, logging the error and returning a pattern that never matches if the regex is
     * invalid.
     *
     * @param regex the regular expression
     * @param context a description of the fact for the error message
     * @return the compiled pattern, or a never matching pattern if the regex is invalid
     */
    static Pattern compilePattern(String regex, String context) {
        try {
            return requireValidPattern(regex, context);
        } catch (IllegalArgumentException e) {
            LOGGER.error("{}", e.getMessage());
            return NEVER_MATCHES;
        }
    }

    static Pattern requireValidPattern(String regex, String context) {
        if (regex == null) {
            throw new IllegalArgumentException("Missing regular expression in " + context);
        }
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException(
                "Invalid regular expression '" + regex + "' in " + context + ": " + e.getMessage(), e);
        }
    }

    @Override
    void validate() {
        compiledPattern = requireValidPattern(pattern, getClass().getSimpleName());
    }

    protected Pattern getCompiledPattern() {
        if (compiledPattern == null) {
            compiledPattern = compilePattern(pattern, getClass().getSimpleName());
        }
        return compiledPattern;
    }

}
