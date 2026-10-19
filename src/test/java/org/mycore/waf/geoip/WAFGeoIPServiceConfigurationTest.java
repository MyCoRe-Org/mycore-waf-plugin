package org.mycore.waf.geoip;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.Before;
import org.junit.Test;
import org.mycore.common.MCRTestCase;
import org.mycore.common.config.MCRConfiguration2;

public class WAFGeoIPServiceConfigurationTest extends MCRTestCase {

    private static final String PREFIX = "MCR.WAF.GeoIP.Database.";

    @Before
    public void configure() {
        MCRConfiguration2.set("MCR.WAF.GeoIP.Directory", "/tmp/waf-geoip-test");
        MCRConfiguration2.set(PREFIX + "downloaded.File", "downloaded.mmdb");
        MCRConfiguration2.set(PREFIX + "downloaded.URL", "https://example.org/downloaded.mmdb");
        MCRConfiguration2.set(PREFIX + "downloaded.ChecksumURL", "https://example.org/downloaded.mmdb.sha256");
        MCRConfiguration2.set(PREFIX + "local.File", "local.mmdb");
        MCRConfiguration2.set(PREFIX + "nofile.URL", "https://example.org/nofile.mmdb");
    }

    private static Map<String, GeoIPDatabase> loadDatabases() {
        return WAFGeoIPService.loadConfiguration().stream()
            .collect(Collectors.toMap(GeoIPDatabase::getName, Function.identity()));
    }

    @Test
    public void databasesAreFoundByTheirProperties() {
        Map<String, GeoIPDatabase> databases = loadDatabases();

        GeoIPDatabase downloaded = databases.get("downloaded");
        assertTrue(downloaded.hasURL());
        assertEquals(Path.of("/tmp/waf-geoip-test", "downloaded.mmdb"), downloaded.getFile());

        GeoIPDatabase local = databases.get("local");
        assertFalse("a database without URL only reads its local file", local.hasURL());
        assertEquals(Path.of("/tmp/waf-geoip-test", "local.mmdb"), local.getFile());

        assertFalse("a database without File is ignored", databases.containsKey("nofile"));
    }

    @Test
    public void emptyDirectoryDisablesGeoIP() {
        MCRConfiguration2.set("MCR.WAF.GeoIP.Directory", "");
        assertEquals(List.of(), WAFGeoIPService.loadConfiguration());
    }

    @Test
    public void unusableDatabasesAreNotLookedUp() {
        WAFGeoIPService service = new WAFGeoIPService(WAFGeoIPService.loadConfiguration());
        assertNull("not configured", service.lookup("unknown", "141.35.1.1"));
        assertNull("no URL and no local file", service.lookup("local", "141.35.1.1"));
    }

}
