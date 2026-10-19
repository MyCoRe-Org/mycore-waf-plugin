package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Root element of a suspicion rule file. Contains any number of {@code rule} elements. A client
 * that solved the Proof of Work challenge is considered suspicious if at least one rule matches.
 */
@XmlRootElement(name = "suspicion-list")
@XmlAccessorType(XmlAccessType.FIELD)
public class SuspicionList {

    /** The XML namespace of the suspicion rule documents. */
    public static final String NAMESPACE = "http://www.mycore.org/waf/suspicion";

    @XmlElement(name = "rule")
    private List<SuspicionRule> rules = new ArrayList<>();

    /**
     * Returns the names of all rules that match the given client information.
     *
     * @param information the client information and the request that submitted it
     * @return the names of the matching rules, empty if the client is not suspicious
     */
    public List<String> findMatchingRules(ClientInformation information) {
        return rules.stream().filter(rule -> rule.matches(information)).map(SuspicionRule::getName).toList();
    }

    /**
     * Returns the names of the GeoIP databases the rules look up.
     *
     * @return the database names, empty if no rule uses a GeoIP fact
     */
    public Set<String> getGeoIPDatabases() {
        Set<String> databases = new TreeSet<>();
        rules.forEach(rule -> rule.collectGeoIPDatabases(databases));
        return databases;
    }

    /**
     * Validates all rules before this suspicion list is used.
     *
     * @throws IllegalArgumentException if a rule is not semantically valid
     */
    public void validate() {
        rules.forEach(SuspicionRule::validate);
    }

    public List<SuspicionRule> getRules() {
        return rules;
    }

}
