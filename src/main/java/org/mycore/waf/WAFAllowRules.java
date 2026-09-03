package org.mycore.waf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.MCRClassTools;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.waf.fact.AllowList;
import org.xml.sax.SAXException;

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

    private static final Logger LOGGER = LogManager.getLogger();

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
        List<AllowList> allowLists = new ArrayList<>();
        String resources = MCRConfiguration2.getString(CONFIG_ALLOWED_RULES).orElse("");
        for (String resource : resources.split(",")) {
            resource = resource.trim();
            if (resource.isEmpty()) {
                continue;
            }
            AllowList allowList = loadAllowList(resource);
            if (allowList != null) {
                allowLists.add(allowList);
            }
        }
        return new WAFAllowRules(allowLists);
    }

    /**
     * Unmarshals a single allow list document from a classpath resource, using the classloader
     * provided by {@link MCRClassTools}.
     *
     * @param resource the classpath resource to load
     * @return the unmarshaled allow list, or null if the resource is missing, invalid or cannot be parsed
     */
    public static AllowList loadAllowList(String resource) {
        ClassLoader classLoader = MCRClassTools.getClassLoader();
        try (InputStream input = classLoader.getResourceAsStream(resource);
            InputStream schemaInput = classLoader.getResourceAsStream(SCHEMA_RESOURCE)) {
            if (input == null) {
                LOGGER.error("WAF allow rule resource {} was not found on the classpath", resource);
                return null;
            }
            if (schemaInput == null) {
                LOGGER.error("WAF allow rule schema {} was not found on the classpath", SCHEMA_RESOURCE);
                return null;
            }
            JAXBContext context = JAXBContext.newInstance(AllowList.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            unmarshaller.setSchema(schemaFactory.newSchema(new StreamSource(schemaInput)));
            AllowList allowList = (AllowList) unmarshaller.unmarshal(input);
            allowList.validate();
            LOGGER.info("Loaded {} WAF allow rules from {}", allowList.getRules().size(), resource);
            return allowList;
        } catch (JAXBException | IOException | SAXException | IllegalArgumentException e) {
            LOGGER.error("Could not load WAF allow rules from classpath resource {}", resource, e);
            return null;
        }
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
