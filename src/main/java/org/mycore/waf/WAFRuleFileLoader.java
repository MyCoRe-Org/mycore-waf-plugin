package org.mycore.waf;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.MCRClassTools;
import org.xml.sax.SAXException;

/**
 * Loads XML rule documents (allow rules, suspicion rules) from classpath resources with JAXB and
 * validates them against the schema generated from the JAXB model.
 */
final class WAFRuleFileLoader {

    private static final Logger LOGGER = LogManager.getLogger();

    private WAFRuleFileLoader() {
    }

    /**
     * Loads all documents listed in a comma separated value of classpath resources. Documents that
     * cannot be loaded are logged and skipped.
     *
     * @param resources comma separated list of classpath resources
     * @param rootClass the JAXB root class of the documents
     * @param schemaResource the classpath resource of the XML schema
     * @param validator semantic validation of a loaded document, throws IllegalArgumentException
     * @return the loaded documents
     */
    static <T> List<T> loadAll(String resources, Class<T> rootClass, String schemaResource,
        Consumer<T> validator) {
        List<T> documents = new ArrayList<>();
        for (String resource : resources.split(",")) {
            resource = resource.trim();
            if (resource.isEmpty()) {
                continue;
            }
            T document = load(resource, rootClass, schemaResource, validator);
            if (document != null) {
                documents.add(document);
            }
        }
        return documents;
    }

    /**
     * Unmarshals a single document from a classpath resource, using the classloader provided by
     * {@link MCRClassTools}.
     *
     * @param resource the classpath resource to load
     * @param rootClass the JAXB root class of the document
     * @param schemaResource the classpath resource of the XML schema
     * @param validator semantic validation of the loaded document, throws IllegalArgumentException
     * @return the unmarshaled document, or null if the resource is missing, invalid or cannot be parsed
     */
    static <T> T load(String resource, Class<T> rootClass, String schemaResource, Consumer<T> validator) {
        ClassLoader classLoader = MCRClassTools.getClassLoader();
        try (InputStream input = classLoader.getResourceAsStream(resource);
            InputStream schemaInput = classLoader.getResourceAsStream(schemaResource)) {
            if (input == null) {
                LOGGER.error("WAF rule resource {} was not found on the classpath", resource);
                return null;
            }
            if (schemaInput == null) {
                LOGGER.error("WAF rule schema {} was not found on the classpath", schemaResource);
                return null;
            }
            JAXBContext context = JAXBContext.newInstance(rootClass);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            unmarshaller.setSchema(schemaFactory.newSchema(new StreamSource(schemaInput)));
            T document = rootClass.cast(unmarshaller.unmarshal(input));
            validator.accept(document);
            LOGGER.info("Loaded WAF {} from {}", rootClass.getSimpleName(), resource);
            return document;
        } catch (JAXBException | IOException | SAXException | IllegalArgumentException e) {
            LOGGER.error("Could not load WAF rules from classpath resource {}", resource, e);
            return null;
        }
    }

}
