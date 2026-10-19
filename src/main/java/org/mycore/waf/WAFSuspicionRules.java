package org.mycore.waf;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.waf.suspicion.ClientInformation;
import org.mycore.waf.suspicion.GeoIPLookup;
import org.mycore.waf.suspicion.SuspicionList;

/**
 * Loads the XML based suspicion rules from classpath resources and evaluates them against the
 * client information of a solved Proof of Work challenge. The property
 * {@link #CONFIG_SUSPICION_RULES} contains a comma separated list of classpath resources, each
 * holding a {@code suspicion-list} document in the namespace
 * {@code http://www.mycore.org/waf/suspicion}. A client that matches any rule has to solve an
 * additional interaction challenge before it gets the WAF-PASSED cookie. If the property is empty,
 * no client is considered suspicious.
 */
public class WAFSuspicionRules {

    /** Comma separated list of classpath resources with suspicion rule documents. */
    public static final String CONFIG_SUSPICION_RULES = "MCR.WAF.SuspicionRules";

    private static final String SCHEMA_RESOURCE = "waf/suspicion-list.xsd";

    private final List<SuspicionList> suspicionLists;

    private final Gson gson = new Gson();

    WAFSuspicionRules(List<SuspicionList> suspicionLists) {
        this.suspicionLists = suspicionLists;
    }

    /**
     * Loads all suspicion rule files configured in {@link #CONFIG_SUSPICION_RULES} from the
     * classpath.
     *
     * @return the loaded suspicion rules, without any suspicion lists if the property is not set
     */
    public static WAFSuspicionRules load() {
        String resources = MCRConfiguration2.getString(CONFIG_SUSPICION_RULES).orElse("");
        return new WAFSuspicionRules(WAFRuleFileLoader.loadAll(resources, SuspicionList.class,
            SCHEMA_RESOURCE, SuspicionList::validate));
    }

    /**
     * Unmarshals a single suspicion list document from a classpath resource.
     *
     * @param resource the classpath resource to load
     * @return the unmarshaled suspicion list, or null if the resource is missing, invalid or cannot be parsed
     */
    public static SuspicionList loadSuspicionList(String resource) {
        return WAFRuleFileLoader.load(resource, SuspicionList.class, SCHEMA_RESOURCE, SuspicionList::validate);
    }

    /**
     * Checks if no suspicion rules are loaded.
     *
     * @return true if no client can be considered suspicious
     */
    public boolean isEmpty() {
        return suspicionLists.isEmpty();
    }

    /**
     * Evaluates all suspicion rules against the client information of a solved challenge.
     *
     * @param request the challenge solution request
     * @param clientInformation the JSON client information gathered by the challenge page
     * @param remoteAddress the client IP address
     * @param redirectURL the URL the client originally requested
     * @param geoIP the lookup in the GeoIP databases
     * @return the names of all matching rules, empty if the client is not suspicious
     */
    public List<String> findMatchingRules(HttpServletRequest request, String clientInformation,
        String remoteAddress, String redirectURL, GeoIPLookup geoIP) {
        if (suspicionLists.isEmpty()) {
            return List.of();
        }
        JsonObject json;
        try {
            json = gson.fromJson(clientInformation, JsonObject.class);
        } catch (JsonParseException | ClassCastException e) {
            json = null;
        }
        if (json == null) {
            // BotDetectionService already rejects unparsable information, this is only a safeguard
            return List.of("unparsable-client-information");
        }
        ClientInformation information = new ClientInformation(json, request, remoteAddress, redirectURL, geoIP);
        List<String> matchingRules = new ArrayList<>();
        for (SuspicionList suspicionList : suspicionLists) {
            matchingRules.addAll(suspicionList.findMatchingRules(information));
        }
        return matchingRules;
    }

}
