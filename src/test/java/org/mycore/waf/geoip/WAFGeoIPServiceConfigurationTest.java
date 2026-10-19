package org.mycore.waf.geoip;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mycore.common.MCRTestCase;
import org.mycore.common.config.MCRConfiguration2;

public class WAFGeoIPServiceConfigurationTest extends MCRTestCase {

    private static final String PREFIX = "MCR.WAF.GeoIP.Database.";

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private Path directory;

    private final List<String> warnings = new CopyOnWriteArrayList<>();

    private AbstractAppender appender;

    @Before
    public void configure() {
        directory = folder.getRoot().toPath();
        MCRConfiguration2.set("MCR.WAF.GeoIP.Directory", directory.toString());
        MCRConfiguration2.set(PREFIX + "downloaded.File", "downloaded.mmdb");
        MCRConfiguration2.set(PREFIX + "downloaded.URL", "https://example.org/downloaded.mmdb");
        MCRConfiguration2.set(PREFIX + "downloaded.ChecksumURL", "https://example.org/downloaded.mmdb.sha256");
        MCRConfiguration2.set(PREFIX + "local.File", "local.mmdb");
        MCRConfiguration2.set(PREFIX + "nofile.URL", "https://example.org/nofile.mmdb");

        appender = new AbstractAppender("GeoIPWarnings", null, null, true, Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                if (event.getLevel() == Level.WARN) {
                    warnings.add(event.getMessage().getFormattedMessage());
                }
            }
        };
        appender.start();
        ((Logger) LogManager.getLogger(WAFGeoIPService.class)).addAppender(appender);
    }

    @After
    public void removeAppender() {
        ((Logger) LogManager.getLogger(WAFGeoIPService.class)).removeAppender(appender);
        appender.stop();
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
        assertEquals(directory.resolve("downloaded.mmdb"), downloaded.getFile());

        GeoIPDatabase local = databases.get("local");
        assertFalse("a database without URL only reads its local file", local.hasURL());
        assertEquals(directory.resolve("local.mmdb"), local.getFile());

        assertFalse("a database without File is ignored", databases.containsKey("nofile"));
    }

    @Test
    public void emptyDirectoryDisablesGeoIP() {
        MCRConfiguration2.set("MCR.WAF.GeoIP.Directory", "");
        assertEquals(List.of(), WAFGeoIPService.loadConfiguration());
    }

    @Test
    public void unusableDatabasesAreReportedOnce() {
        WAFGeoIPService service = new WAFGeoIPService(WAFGeoIPService.loadConfiguration());

        for (int i = 0; i < 3; i++) {
            assertNull(service.lookup("unknown", "141.35.1.1"));
            assertNull(service.lookup("local", "141.35.1.1"));
        }

        assertEquals(warnings.toString(), 2, warnings.size());
        assertTrue(warnings.get(0),
            warnings.get(0).contains("'unknown'") && warnings.get(0).contains("not configured"));
        assertTrue(warnings.get(1), warnings.get(1).contains("'local'") && warnings.get(1).contains("no local file"));
    }

    @Test
    public void disabledGeoIPIsNamedAsReason() {
        MCRConfiguration2.set("MCR.WAF.GeoIP.Directory", "");
        WAFGeoIPService service = new WAFGeoIPService(WAFGeoIPService.loadConfiguration());

        assertNull(service.lookup("country", "141.35.1.1"));
        assertNull(service.lookup("country", "141.35.1.1"));

        assertEquals(warnings.toString(), 1, warnings.size());
        assertTrue(warnings.get(0), warnings.get(0).contains("GeoIP is disabled")
            && warnings.get(0).contains("MCR.WAF.GeoIP.Directory is empty"));
    }

}
