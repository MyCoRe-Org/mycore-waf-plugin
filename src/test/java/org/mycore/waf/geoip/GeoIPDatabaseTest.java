package org.mycore.waf.geoip;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GeoIPDatabaseTest {

    private static final String COUNTRY_TEST_DB = "waf/geoip/GeoLite2-Country-Test.mmdb";

    private static final String ASN_TEST_DB = "waf/geoip/GeoLite2-ASN-Test.mmdb";

    @TempDir
    Path directory;

    private HttpServer server;

    private final Map<String, byte[]> served = new ConcurrentHashMap<>();

    private final Map<String, AtomicInteger> requests = new ConcurrentHashMap<>();

    private final HttpClient client = HttpClient.newHttpClient();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            requests.computeIfAbsent(path, key -> new AtomicInteger()).incrementAndGet();
            byte[] body = served.get(path);
            if (body == null) {
                exchange.sendResponseHeaders(404, -1);
            } else {
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream output = exchange.getResponseBody()) {
                    output.write(body);
                }
            }
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream input = GeoIPDatabaseTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(input, name);
            return input.readAllBytes();
        }
    }

    private URI uri(String path) {
        return URI.create("http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort() + path);
    }

    private void serve(String path, byte[] database) throws IOException {
        served.put(path, database);
        Path temporary = Files.write(directory.resolve("checksum-input"), database);
        String checksum = GeoIPDatabase.checksum(temporary);
        served.put(path + ".sha256", (checksum + "  db.mmdb\n").getBytes(StandardCharsets.UTF_8));
    }

    private int requestCount(String path) {
        AtomicInteger count = requests.get(path);
        return count == null ? 0 : count.get();
    }

    private static InetAddress address(String ip) throws IOException {
        return InetAddress.getByName(ip);
    }

    @Test
    void localFileIsLoadedWithoutURL() throws Exception {
        Path file = Files.write(directory.resolve("country.mmdb"), resource(COUNTRY_TEST_DB));
        GeoIPDatabase database = new GeoIPDatabase("country", file, null, null, Duration.ofDays(1));
        assertFalse(database.isAvailable());
        database.update(client);
        assertTrue(database.isAvailable());
        assertEquals("GB", ((Map<?, ?>) database.lookup(address("81.2.69.160")).get("country")).get("iso_code"));
        assertNull(database.lookup(address("10.0.0.1")));
    }

    @Test
    void databaseIsDownloadedAndVerified() throws Exception {
        serve("/asn.mmdb", resource(ASN_TEST_DB));
        Path file = directory.resolve("sub/asn.mmdb");
        GeoIPDatabase database = new GeoIPDatabase("asn", file, uri("/asn.mmdb"), uri("/asn.mmdb.sha256"),
            Duration.ofDays(1));

        database.update(client);

        assertTrue(Files.isRegularFile(file));
        assertArrayEquals(resource(ASN_TEST_DB), Files.readAllBytes(file));
        Map<String, Object> record = database.lookup(address("81.128.0.1"));
        assertEquals(2856L, record.get("autonomous_system_number"));
        assertEquals(1, requestCount("/asn.mmdb"));
        try (var files = Files.list(file.getParent())) {
            assertEquals(List.of(file), files.toList(), "no temporary files are left");
        }
    }

    @Test
    void unchangedDatabaseIsNotDownloadedAgain() throws Exception {
        serve("/asn.mmdb", resource(ASN_TEST_DB));
        Path file = directory.resolve("asn.mmdb");
        GeoIPDatabase database = new GeoIPDatabase("asn", file, uri("/asn.mmdb"), uri("/asn.mmdb.sha256"),
            Duration.ofDays(1));
        database.update(client);
        database.update(client);

        // A restarted application loads the local file and does not download it either
        GeoIPDatabase restarted = new GeoIPDatabase("asn", file, uri("/asn.mmdb"), uri("/asn.mmdb.sha256"),
            Duration.ofDays(1));
        restarted.update(client);

        assertEquals(1, requestCount("/asn.mmdb"));
        assertEquals(3, requestCount("/asn.mmdb.sha256"));
        assertTrue(restarted.isAvailable());
    }

    @Test
    void changedDatabaseReplacesTheOldOne() throws Exception {
        serve("/db.mmdb", resource(ASN_TEST_DB));
        Path file = directory.resolve("db.mmdb");
        GeoIPDatabase database = new GeoIPDatabase("db", file, uri("/db.mmdb"), uri("/db.mmdb.sha256"),
            Duration.ofDays(1));
        database.update(client);
        assertNotNull(database.lookup(address("81.128.0.1")).get("autonomous_system_number"));

        serve("/db.mmdb", resource(COUNTRY_TEST_DB));
        database.update(client);

        assertEquals(2, requestCount("/db.mmdb"));
        assertNotNull(database.lookup(address("81.2.69.160")).get("country"));
        assertArrayEquals(resource(COUNTRY_TEST_DB), Files.readAllBytes(file));
    }

    @Test
    void wrongChecksumKeepsTheOldDatabase() throws Exception {
        Path file = Files.write(directory.resolve("db.mmdb"), resource(COUNTRY_TEST_DB));
        serve("/db.mmdb", resource(ASN_TEST_DB));
        served.put("/db.mmdb.sha256", ("0".repeat(64) + "  db.mmdb").getBytes(StandardCharsets.UTF_8));
        GeoIPDatabase database = new GeoIPDatabase("db", file, uri("/db.mmdb"), uri("/db.mmdb.sha256"),
            Duration.ofDays(1));

        IOException exception = assertThrows(IOException.class, () -> database.update(client));

        assertTrue(exception.getMessage().contains("Checksum"));
        assertArrayEquals(resource(COUNTRY_TEST_DB), Files.readAllBytes(file));
        assertNotNull(database.lookup(address("81.2.69.160")), "the local database is still used");
    }

    @Test
    void invalidDownloadIsRejected() throws Exception {
        serve("/db.mmdb", "no database".getBytes(StandardCharsets.UTF_8));
        Path file = directory.resolve("db.mmdb");
        GeoIPDatabase database = new GeoIPDatabase("db", file, uri("/db.mmdb"), uri("/db.mmdb.sha256"),
            Duration.ofDays(1));

        assertThrows(IOException.class, () -> database.update(client));

        assertFalse(Files.exists(file));
        assertFalse(database.isAvailable());
    }

    @Test
    void failedDownloadIsReported() {
        GeoIPDatabase database = new GeoIPDatabase("db", directory.resolve("db.mmdb"), uri("/missing.mmdb"),
            uri("/missing.mmdb.sha256"), Duration.ofDays(1));
        IOException exception = assertThrows(IOException.class, () -> database.update(client));
        assertTrue(exception.getMessage().contains("404"));
    }

    @Test
    void withoutChecksumOnlyOldFilesAreDownloaded() throws Exception {
        serve("/db.mmdb", resource(ASN_TEST_DB));
        Path file = directory.resolve("db.mmdb");
        GeoIPDatabase database = new GeoIPDatabase("db", file, uri("/db.mmdb"), null, Duration.ofDays(1));
        database.update(client);
        database.update(client);
        assertEquals(1, requestCount("/db.mmdb"));
    }

    @Test
    void privateAddressesAreNotLookedUp() {
        for (String address : List.of("10.1.2.3", "172.16.0.1", "192.168.178.20", "127.0.0.1", "169.254.10.10",
            "100.64.1.1", "100.127.255.255", "0.0.0.0", "::1", "fd12:3456::1", "fe80::1", "224.0.0.1",
            "example.org", "")) {
            assertNull(WAFGeoIPService.parsePublicAddress(address), address);
        }
        for (String address : List.of("141.35.1.1", "100.63.255.255", "100.128.0.1", "2a00:1450:4001::1")) {
            assertNotNull(WAFGeoIPService.parsePublicAddress(address), address);
        }
    }

    @Test
    void serviceLooksUpConfiguredDatabases() throws Exception {
        Path file = Files.write(directory.resolve("country.mmdb"), resource(COUNTRY_TEST_DB));
        GeoIPDatabase database = new GeoIPDatabase("country", file, null, null, Duration.ofDays(1));
        database.load();
        WAFGeoIPService service = new WAFGeoIPService(List.of(database));

        assertNotNull(service.lookup("country", "81.2.69.160"));
        assertNull(service.lookup("asn", "81.2.69.160"), "unknown database");
        assertNull(service.lookup("country", "192.168.1.1"), "private address");
        assertNull(service.lookup("country", null));
    }

}
