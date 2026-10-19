package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.List;
import java.util.regex.Pattern;
import org.mycore.waf.WAFRegex;

/**
 * Base class for facts that match a Java regex against values. The regex must match a whole
 * value, not just a part of it. If several values are present, the fact is true if any value
 * matches ({@code match="any"}, the default) or if all values match ({@code match="all"}). A fact
 * without values never matches.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class PatternFact extends ClientFact {

    @XmlAttribute(required = true)
    private String pattern;

    @XmlAttribute
    private MatchMode match = MatchMode.ANY;

    private transient volatile Pattern compiledPattern;

    @Override
    public boolean matches(ClientInformation information) {
        List<String> values = getValues(information);
        if (values.isEmpty()) {
            return false;
        }
        Pattern p = getCompiledPattern();
        if (match == MatchMode.ALL) {
            return values.stream().allMatch(value -> p.matcher(value).matches());
        }
        return values.stream().anyMatch(value -> p.matcher(value).matches());
    }

    /**
     * Returns the values this fact is matched against.
     *
     * @param information the client information and the request that submitted it
     * @return the values, empty if nothing is present
     */
    protected abstract List<String> getValues(ClientInformation information);

    private Pattern getCompiledPattern() {
        if (compiledPattern == null) {
            compiledPattern = compile();
        }
        return compiledPattern;
    }

    private Pattern compile() {
        return WAFRegex.requireValidPattern(pattern, getClass().getSimpleName());
    }

    @Override
    void validate() {
        compiledPattern = compile();
    }

}
