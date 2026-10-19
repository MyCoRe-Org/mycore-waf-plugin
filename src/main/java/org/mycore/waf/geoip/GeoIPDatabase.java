package org.mycore.waf.geoip;

import com.maxmind.db.Reader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A single GeoIP database in the MaxMind DB (MMDB) format. The database is read from a local file
 * into memory. If a download URL is configured, {@link #update(HttpClient)} downloads a new version
 * and replaces the local file and the database in memory without interrupting lookups.
 * <p>
 * If a checksum URL is configured, the update first fetches the SHA-256 checksum (in the format of
 * {@code sha256sum}) and downloads the database only if the checksum differs from the local file.
 * The downloaded file is only used if it matches the checksum. Without checksum URL the database
 * is downloaded whenever the local file is older than the update interval.
 */
public class GeoIPDatabase {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofMinutes(5);

    private final String name;

    private final Path file;

    private final URI url;

    private final URI checksumURL;

    private final Duration maxAge;

    private final Duration requestTimeout;

    private volatile Reader reader;

    private volatile String fileChecksum;

    /**
     * Creates a database. Nothing is loaded until {@link #load()} or {@link #update(HttpClient)} is
     * called.
     *
     * @param name the name the database is referenced by in suspicion rules
     * @param file the local file of the database
     * @param url the download URL, or null to only use the local file
     * @param checksumURL the URL of the SHA-256 checksum of the download, or null
     * @param maxAge the age of the local file after which it is downloaded again if there is no checksum URL
     */
    public GeoIPDatabase(String name, Path file, URI url, URI checksumURL, Duration maxAge) {
        this(name, file, url, checksumURL, maxAge, DEFAULT_REQUEST_TIMEOUT);
    }

    /**
     * Creates a database with a custom timeout for each download, including the response body.
     *
     * @param name the name the database is referenced by in suspicion rules
     * @param file the local file of the database
     * @param url the download URL, or null to only use the local file
     * @param checksumURL the URL of the SHA-256 checksum of the download, or null
     * @param maxAge the age of the local file after which it is downloaded again if there is no checksum URL
     * @param requestTimeout the maximal duration of one download
     */
    GeoIPDatabase(String name, Path file, URI url, URI checksumURL, Duration maxAge, Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
        this.name = name;
        this.file = file;
        this.url = url;
        this.checksumURL = checksumURL;
        this.maxAge = maxAge;
    }

    public String getName() {
        return name;
    }

    /**
     * Checks if the database has been loaded.
     *
     * @return true if lookups are possible
     */
    public boolean isAvailable() {
        return reader != null;
    }

    /**
     * Looks up an IP address.
     *
     * @param address the IP address
     * @return the database record, or null if the database is not loaded or the address is not contained
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> lookup(InetAddress address) {
        Reader current = reader;
        if (current == null) {
            return null;
        }
        try {
            return current.get(address, Map.class);
        } catch (IOException e) {
            LOGGER.warn("GeoIP lookup of {} in database '{}' failed", address.getHostAddress(), name, e);
            return null;
        }
    }

    /**
     * Loads the local file, if it exists and the database has not been loaded yet.
     */
    public void load() {
        if (reader != null || !Files.isRegularFile(file)) {
            return;
        }
        try {
            String checksum = checksum(file);
            Reader loaded = open(file);
            fileChecksum = checksum;
            reader = loaded;
            LOGGER.info("Loaded GeoIP database '{}' from {} (built {})", name, file,
                loaded.getMetadata().buildTime());
        } catch (IOException e) {
            LOGGER.error("Could not load GeoIP database '{}' from {}", name, file, e);
        }
    }

    /**
     * Downloads a new version of the database if one is available and replaces the local file and
     * the database in memory. Without download URL only the local file is loaded.
     *
     * @param client the HTTP client to use
     * @throws IOException if the download fails or the downloaded file is invalid
     * @throws InterruptedException if the thread is interrupted while downloading
     */
    public void update(HttpClient client) throws IOException, InterruptedException {
        load();
        if (url == null) {
            return;
        }
        String expectedChecksum = null;
        if (checksumURL != null) {
            expectedChecksum = fetchChecksum(client);
            if (expectedChecksum.equals(fileChecksum) && reader != null) {
                LOGGER.debug("GeoIP database '{}' is up to date", name);
                return;
            }
        } else if (reader != null && Files.getLastModifiedTime(file).toInstant()
            .isAfter(Instant.now().minus(maxAge))) {
            LOGGER.debug("GeoIP database '{}' is younger than {}, not downloading", name, maxAge);
            return;
        }

        Files.createDirectories(file.getParent());
        Path temporary = Files.createTempFile(file.getParent(), file.getFileName().toString(), ".download");
        try {
            String downloadedChecksum = download(client, temporary);
            if (expectedChecksum != null && !expectedChecksum.equals(downloadedChecksum)) {
                throw new IOException("Checksum of downloaded GeoIP database '" + name + "' is " + downloadedChecksum
                    + ", expected " + expectedChecksum);
            }
            // Opening validates the file before it replaces the working one
            Reader downloaded = open(temporary);
            move(temporary, file);
            fileChecksum = downloadedChecksum;
            // The old reader holds no file handle in memory mode and is left to the garbage collector,
            // closing it could break lookups that are still running
            reader = downloaded;
            LOGGER.info("Updated GeoIP database '{}' from {} (built {})", name, url,
                downloaded.getMetadata().buildTime());
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private String fetchChecksum(HttpClient client) throws IOException, InterruptedException {
        HttpResponse<String> response = send(client, checksumURL,
            HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new IOException("Fetching " + checksumURL + " failed with HTTP status " + response.statusCode());
        }
        // Format of sha256sum: "<hex>  <file name>"
        String checksum = response.body().trim().split("\\s+")[0].toLowerCase(Locale.ROOT);
        if (!checksum.matches("[0-9a-f]{64}")) {
            throw new IOException("Invalid SHA-256 checksum in " + checksumURL);
        }
        return checksum;
    }

    private String download(HttpClient client, Path target) throws IOException, InterruptedException {
        HttpResponse<Path> response = send(client, url, HttpResponse.BodyHandlers.ofFile(target));
        if (response.statusCode() != 200) {
            throw new IOException("Downloading " + url + " failed with HTTP status " + response.statusCode());
        }
        return checksum(target);
    }

    /**
     * Sends a request and waits for the complete response body. HttpRequest.timeout only limits the
     * wait for the response headers, a stalled body would block the update thread forever.
     */
    private <T> HttpResponse<T> send(HttpClient client, URI uri, HttpResponse.BodyHandler<T> bodyHandler)
        throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<T>> future = client.sendAsync(request(uri), bodyHandler);
        try {
            return future.get(requestTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new IOException("Request to " + uri + " did not complete within " + requestTimeout, e);
        } catch (InterruptedException e) {
            future.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            throw new IOException("Request to " + uri + " failed: " + e.getCause().getMessage(), e.getCause());
        }
    }

    private HttpRequest request(URI uri) {
        return HttpRequest.newBuilder(uri)
            .timeout(requestTimeout)
            .header("User-Agent", "MyCoRe-WAF-Plugin")
            .GET()
            .build();
    }

    private static Reader open(Path path) throws IOException {
        return new Reader(path.toFile(), Reader.FileMode.MEMORY);
    }

    private static void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    static String checksum(Path path) throws IOException {
        MessageDigest digest = sha256();
        try (InputStream input = new DigestInputStream(Files.newInputStream(path), digest)) {
            input.transferTo(OutputStream.nullOutputStream());
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not supported", e);
        }
    }

}
