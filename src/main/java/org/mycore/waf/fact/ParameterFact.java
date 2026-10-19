package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A fact that checks a request parameter. Without a {@code pattern} the fact is true if a
 * parameter with the given name exists. With a {@code pattern} it is true if at least one value of
 * the parameter matches the regex. Two additional constraints can be enforced:
 * <ul>
 * <li>{@code unique="true"}: the parameter name occurs exactly once in the whole request, so
 * {@code ?style=xml} is accepted while {@code ?style=xml&style=json} is rejected.</li>
 * <li>{@code sole="true"}: no other parameter name exists in the request, so
 * {@code ?style=xml} is accepted while {@code ?style=xml&foo=bar} is rejected.</li>
 * </ul>
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ParameterFact extends Fact {

    @XmlAttribute(required = true)
    private String name;

    @XmlAttribute
    private String pattern;

    @XmlAttribute
    private Boolean unique;

    @XmlAttribute
    private Boolean sole;

    private transient volatile Pattern compiledPattern;

    @Override
    public boolean matches(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        String[] values = parameterMap.get(name);
        if (values == null) {
            return false;
        }
        if (Boolean.TRUE.equals(sole) && parameterMap.size() != 1) {
            return false;
        }
        if (Boolean.TRUE.equals(unique) && values.length != 1) {
            return false;
        }
        if (pattern == null) {
            return true;
        }
        Pattern p = getCompiledPattern();
        if (p == null) {
            return false;
        }
        for (String value : values) {
            if (value != null && p.matcher(value).matches()) {
                return true;
            }
        }
        return false;
    }

    private Pattern getCompiledPattern() {
        if (compiledPattern == null && pattern != null) {
            compiledPattern = RegexFact.compilePattern(pattern, "parameter fact");
        }
        return compiledPattern;
    }

    @Override
    void validate() {
        if (pattern != null) {
            compiledPattern = RegexFact.requireValidPattern(pattern, "parameter fact");
        }
    }

}
