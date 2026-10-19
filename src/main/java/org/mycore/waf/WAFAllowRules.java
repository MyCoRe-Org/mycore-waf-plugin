package org.mycore.waf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.mycore.common.MCRClassTools;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.waf.fact.AllowList;

/**
 * Loads the XML based allow rules from classpath resources and evaluates them against incoming
 * requests. The property {@link #CONFIG_ALLOWED_RULES} contains a comma separated list of
 * classpath resources, each holding an {@code allow-list} document in the namespace
 * {@code http://www.mycore.org/waf}. A request that matches any rule of any loaded allow list
 * bypasses the WAF challenge. If the property is not set, no rules are loaded and the behavior of
 * the WAF is unchanged.
 */
public class WAFAllowRules {

    /** Comma separated list of classpath resources with allow rule documents. */
    public static final String CONFIG_ALLOWED_RULES = "MCR.WAF.AllowedRules";

    private static final String SCHEMA_RESOURCE = "waf/allow-list.xsd";

    private final List<AllowList> allowLists;

    private WAFAllowRules(List<AllowList> allowLists) {
        this.allowLists = allowLists;
    }

    /**
     * Loads all allow rule files configured in {@link #CONFIG_ALLOWED_RULES} from the classpath.
     *
     * @return the loaded allow rules, without any allow lists if the property is not set
     */
    public static WAFAllowRules load() {
        String resources = MCRConfiguration2.getString(CONFIG_ALLOWED_RULES).orElse("");
        return new WAFAllowRules(WAFRuleFileLoader.loadAll(resources, AllowList.class, SCHEMA_RESOURCE,
            AllowList::validate));
    }

    /**
     * Unmarshals a single allow list document from a classpath resource, using the classloader
     * provided by {@link MCRClassTools}.
     *
     * @param resource the classpath resource to load
     * @return the unmarshaled allow list, or null if the resource is missing, invalid or cannot be parsed
     */
    public static AllowList loadAllowList(String resource) {
        return WAFRuleFileLoader.load(resource, AllowList.class, SCHEMA_RESOURCE, AllowList::validate);
    }

    /**
     * Checks if the request matches any rule of the loaded allow lists.
     *
     * @param request the incoming HTTP request
     * @return true if any rule matches, false otherwise
     */
    public boolean isAllowed(HttpServletRequest request) {
        for (AllowList allowList : allowLists) {
            if (allowList.isAllowed(request)) {
                return true;
            }
        }
        return false;
    }

}
