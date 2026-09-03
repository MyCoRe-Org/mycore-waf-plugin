package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlEnum;
import jakarta.xml.bind.annotation.XmlEnumValue;
import java.util.Map;

/**
 * A fact that checks the number of request parameters. By default distinct parameter names are
 * counted ({@code mode="names"}), with {@code mode="values"} the total number of parameter
 * occurrences is counted instead. The count can be constrained to an exact {@code value}, or to a
 * range via {@code min} and {@code max}. Multiple constraints are combined.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ParameterCountFact extends Fact {

    /**
     * What to count: distinct parameter names or total parameter occurrences.
     */
    @XmlEnum(String.class)
    public enum CountMode {
        @XmlEnumValue("names")
        NAMES,
        @XmlEnumValue("values")
        VALUES
    }

    @XmlAttribute
    private Integer value;

    @XmlAttribute
    private Integer min;

    @XmlAttribute
    private Integer max;

    @XmlAttribute
    private CountMode mode = CountMode.NAMES;

    @Override
    public boolean matches(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        int count = mode == CountMode.VALUES
            ? parameterMap.values().stream().mapToInt(values -> values.length).sum()
            : parameterMap.size();
        if (value != null && count != value) {
            return false;
        }
        if (min != null && count < min) {
            return false;
        }
        if (max != null && count > max) {
            return false;
        }
        return true;
    }

}
