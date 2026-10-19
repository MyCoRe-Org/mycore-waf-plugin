package org.mycore.waf.suspicion;

import java.util.Map;

/**
 * Looks up an IP address in a named GeoIP database, for example {@code country} or {@code asn}.
 */
@FunctionalInterface
public interface GeoIPLookup {

    /** A lookup without any database, every address is unknown. */
    GeoIPLookup NONE = (database, address) -> null;

    /**
     * Looks up an IP address.
     *
     * @param database the configured name of the database
     * @param address the IP address
     * @return the database record, or null if the database is not available, the address is private
     *     or not contained in the database
     */
    Map<String, Object> lookup(String database, String address);

}
