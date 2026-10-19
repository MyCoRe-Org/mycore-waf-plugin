package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.Map;
import java.util.regex.Pattern;
import org.mycore.waf.WAFRegex;

/**
 * Base class for facts that look up the client IP address in a GeoIP database. If the database is
 * not available, the address is private or it is not contained in the database, the fact throws
 * {@link UndeterminableFactException}, so that the rule does not match at all.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class GeoIPFact extends ClientFact {

    @XmlAttribute
    private String database;

    /**
     * Returns the name of the database that is used if the {@code database} attribute is missing.
     *
     * @return the default database name
     */
    protected abstract String getDefaultDatabase();

    private String getDatabaseName() {
        return database == null ? getDefaultDatabase() : database;
    }

    /**
     * Looks up the client IP address.
     *
     * @param information the client information and the request that submitted it
     * @return the database record, never null
     * @throws UndeterminableFactException if there is no record for the address
     */
    protected Map<String, Object> lookup(ClientInformation information) {
        String databaseName = getDatabaseName();
        Map<String, Object> record = information.geoIP().lookup(databaseName, information.remoteAddress());
        if (record == null) {
            throw new UndeterminableFactException(
                "No GeoIP record in database '" + databaseName + "' for " + information.remoteAddress());
        }
        return record;
    }

    /**
     * Reads a value from a database record by a path of map keys.
     *
     * @param record the database record
     * @param path the keys of the nested maps, for example {@code country}, {@code iso_code}
     * @return the value, or null if it does not exist
     */
    protected static Object getValue(Map<String, Object> record, String... path) {
        Object current = record;
        for (String key : path) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = map.get(key);
        }
        return current;
    }

    /**
     * Compiles a regex of this fact.
     *
     * @param regex the regex
     * @param attribute the attribute name for the error message
     * @return the compiled pattern, or null if the regex is null
     */
    protected Pattern compile(String regex, String attribute) {
        return regex == null ? null
            : WAFRegex.requireValidPattern(regex, attribute + " of " + getClass().getSimpleName());
    }

}
