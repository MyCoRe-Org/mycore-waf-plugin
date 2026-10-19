package org.mycore.waf;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Compiles the regular expressions of the XML allow and suspicion rules with a uniform error
 * message.
 */
public final class WAFRegex {

    private WAFRegex() {
    }

    /**
     * Compiles a regular expression.
     *
     * @param regex the regular expression
     * @param context a description of the fact for the error message
     * @return the compiled pattern
     * @throws IllegalArgumentException if the regex is missing or invalid
     */
    public static Pattern requireValidPattern(String regex, String context) {
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

}
