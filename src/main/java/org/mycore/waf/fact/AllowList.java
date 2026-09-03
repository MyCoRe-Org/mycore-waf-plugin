package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

/**
 * Root element of an allow rule file. Contains any number of {@code rule} elements. The request
 * bypasses the WAF challenge if at least one rule of the allow list matches.
 */
@XmlRootElement(name = "allow-list")
@XmlAccessorType(XmlAccessType.FIELD)
public class AllowList {

    /** The XML namespace of the allow rule documents. */
    public static final String NAMESPACE = "http://www.mycore.org/waf";

    @XmlElement(name = "rule")
    private List<AllowRule> rules = new ArrayList<>();

    /**
     * Checks if any rule of this allow list matches the given request.
     *
     * @param request the incoming HTTP request
     * @return true if any rule matches, false otherwise
     */
    public boolean isAllowed(HttpServletRequest request) {
        return rules.stream().anyMatch(rule -> rule.matches(request));
    }

    /**
     * Validates all rules before this allow list is used for request matching.
     *
     * @throws IllegalArgumentException if a rule is not semantically valid
     */
    public void validate() {
        rules.forEach(AllowRule::validate);
    }

    public List<AllowRule> getRules() {
        return rules;
    }

    public void setRules(List<AllowRule> rules) {
        this.rules = rules;
    }

}
