package org.mycore.waf.fact;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.SchemaOutputResolver;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.transform.Result;
import javax.xml.transform.stream.StreamResult;

/**
 * Generates the XML schema for the allow rule documents from the JAXB model. Invoked by the Maven
 * build (exec-maven-plugin, phase process-classes) so that the schema is always in sync with the
 * {@link AllowList} model. The schema is packaged as {@code waf/allow-list.xsd} inside the JAR and
 * can be referenced from rule files via {@code xsi:schemaLocation} to get validation and auto
 * completion in XML editors.
 */
public class AllowListSchemaGenerator {

    /**
     * Writes the schema to the given output path, or to {@code allow-list.xsd} in the working
     * directory if no argument is given.
     *
     * @param args optional output file path
     * @throws Exception if the schema cannot be generated or written
     */
    public static void main(String[] args) throws Exception {
        Path outputPath = args.length > 0 ? Path.of(args[0]) : Path.of("allow-list.xsd");
        if (outputPath.getParent() != null) {
            Files.createDirectories(outputPath.getParent());
        }
        try (OutputStream output = Files.newOutputStream(outputPath)) {
            JAXBContext context = JAXBContext.newInstance(AllowList.class);
            context.generateSchema(new SchemaOutputResolver() {

                @Override
                public Result createOutput(String namespaceUri, String suggestedFileName) {
                    StreamResult result = new StreamResult(output);
                    result.setSystemId(outputPath.toUri().toString());
                    return result;
                }

            });
        }
    }

}
