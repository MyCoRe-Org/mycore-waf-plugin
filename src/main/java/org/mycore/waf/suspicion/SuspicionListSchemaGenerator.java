package org.mycore.waf.suspicion;

import java.nio.file.Path;
import org.mycore.waf.fact.AllowListSchemaGenerator;

/**
 * Generates the XML schema for the suspicion rule documents from the JAXB model. Invoked by the
 * Maven build (exec-maven-plugin, phase process-classes) so that the schema is always in sync with
 * the {@link SuspicionList} model. The schema is packaged as {@code waf/suspicion-list.xsd} inside
 * the JAR.
 */
public class SuspicionListSchemaGenerator {

    /**
     * Writes the schema to the given output path, or to {@code suspicion-list.xsd} in the working
     * directory if no argument is given.
     *
     * @param args optional output file path
     * @throws Exception if the schema cannot be generated or written
     */
    public static void main(String[] args) throws Exception {
        Path outputPath = args.length > 0 ? Path.of(args[0]) : Path.of("suspicion-list.xsd");
        AllowListSchemaGenerator.generateSchema(SuspicionList.class, outputPath);
    }

}
