package org.mycore.waf.geoip;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.common.config.MCRConfigurationException;
import org.mycore.common.events.MCRShutdownHandler;
import org.mycore.waf.suspicion.GeoIPLookup;

/**
 * Provides the GeoIP databases used by the suspicion rules. The databases are configured in
 * {@code MCR.WAF.GeoIP.*}, stored in {@code MCR.WAF.GeoIP.Directory} and updated in a background
 * thread every {@code MCR.WAF.GeoIP.UpdateIntervalHours} hours. Until a database is available,
 * GeoIP facts cannot be evaluated and rules using them do not match.
 * <p>
 * Private, loopback, link local and shared (CGNAT) addresses are never looked up, so GeoIP rules
 * never match local test systems or clients in a VPN with private addresses.
 */
public class WAFGeoIPService implements GeoIPLookup {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String CONFIG_PREFIX = "MCR.WAF.GeoIP.";
    private static final String CONFIG_DIRECTORY = CONFIG_PREFIX + "Directory";
    private static final String CONFIG_DATABASES = CONFIG_PREFIX + "Databases";
    private static final String CONFIG_UPDATE_INTERVAL_HOURS = CONFIG_PREFIX + "UpdateIntervalHours";

    private static final int DEFAULT_UPDATE_INTERVAL_HOURS = 24;

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(30);

    // IP literals only, so that InetAddress.getByName never performs a DNS lookup
    private static final Pattern IP_LITERAL = Pattern.compile("[0-9a-fA-F:.]+");

    // 100.64.0.0/10, shared address space for carrier grade NAT (RFC 6598)
    private static final int CGNAT_PREFIX = 0x64400000;
    private static final int CGNAT_MASK = 0xFFC00000;

    private final Map<String, GeoIPDatabase> databases;

    private ScheduledExecutorService scheduler;

    /**
     * Creates a service for the given databases without starting the update thread.
     *
     * @param databases the databases
     */
    public WAFGeoIPService(List<GeoIPDatabase> databases) {
        this.databases = new LinkedHashMap<>();
        databases.forEach(database -> this.databases.put(database.getName(), database));
    }

    /**
     * Creates the service from the configuration and starts the background thread that loads and
     * updates the databases.
     *
     * @return the started service, or a service without databases if none are configured
     */
    public static WAFGeoIPService start() {
        List<GeoIPDatabase> databases = loadConfiguration();
        WAFGeoIPService service = new WAFGeoIPService(databases);
        if (!databases.isEmpty()) {
            service.startUpdates(MCRConfiguration2.getInt(CONFIG_UPDATE_INTERVAL_HOURS)
                .orElse(DEFAULT_UPDATE_INTERVAL_HOURS));
        }
        return service;
    }

    private static List<GeoIPDatabase> loadConfiguration() {
        List<GeoIPDatabase> databases = new ArrayList<>();
        Optional<String> directory;
        try {
            directory = MCRConfiguration2.getString(CONFIG_DIRECTORY).filter(value -> !value.isBlank());
        } catch (MCRConfigurationException e) {
            LOGGER.warn("GeoIP is disabled, {} cannot be resolved: {}", CONFIG_DIRECTORY, e.getMessage());
            return databases;
        }
        if (directory.isEmpty()) {
            LOGGER.info("GeoIP is disabled, {} is not set", CONFIG_DIRECTORY);
            return databases;
        }
        int intervalHours = MCRConfiguration2.getInt(CONFIG_UPDATE_INTERVAL_HOURS)
            .orElse(DEFAULT_UPDATE_INTERVAL_HOURS);
        for (String name : MCRConfiguration2.getString(CONFIG_DATABASES).orElse("").split(",")) {
            name = name.trim();
            if (name.isEmpty()) {
                continue;
            }
            String prefix = CONFIG_PREFIX + "Database." + name + ".";
            Optional<String> fileName = MCRConfiguration2.getString(prefix + "File");
            if (fileName.isEmpty()) {
                LOGGER.error("GeoIP database '{}' has no {}File, ignoring it", name, prefix);
                continue;
            }
            URI url = MCRConfiguration2.getString(prefix + "URL").filter(value -> !value.isBlank())
                .map(URI::create).orElse(null);
            URI checksumURL = MCRConfiguration2.getString(prefix + "ChecksumURL").filter(value -> !value.isBlank())
                .map(URI::create).orElse(null);
            databases.add(new GeoIPDatabase(name, Path.of(directory.get()).resolve(fileName.get()), url,
                checksumURL, Duration.ofHours(intervalHours)));
        }
        return databases;
    }

    private void startUpdates(int intervalHours) {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "WAF GeoIP Update");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(() -> updateAll(client), 0, intervalHours, TimeUnit.HOURS);
        MCRShutdownHandler.getInstance().addCloseable(this::stop);
    }

    private void updateAll(HttpClient client) {
        for (GeoIPDatabase database : databases.values()) {
            try {
                database.update(client);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                // Keep the old database, it is retried with the next update
                LOGGER.warn("Could not update GeoIP database '{}': {}", database.getName(), e.getMessage());
            }
        }
    }

    /**
     * Stops the background update thread.
     */
    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    /**
     * Checks if any database is configured.
     *
     * @return true if at least one database is configured
     */
    public boolean hasDatabases() {
        return !databases.isEmpty();
    }

    @Override
    public Map<String, Object> lookup(String database, String address) {
        GeoIPDatabase geoIPDatabase = databases.get(database);
        if (geoIPDatabase == null || address == null) {
            return null;
        }
        InetAddress inetAddress = parsePublicAddress(address);
        return inetAddress == null ? null : geoIPDatabase.lookup(inetAddress);
    }

    /**
     * Parses an IP literal and checks that it is a public address.
     *
     * @param address the IP address
     * @return the parsed address, or null if it is no IP literal or not public
     */
    static InetAddress parsePublicAddress(String address) {
        if (!IP_LITERAL.matcher(address).matches()) {
            return null;
        }
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            return null;
        }
        if (inetAddress.isAnyLocalAddress() || inetAddress.isLoopbackAddress() || inetAddress.isLinkLocalAddress()
            || inetAddress.isSiteLocalAddress() || inetAddress.isMulticastAddress()) {
            return null;
        }
        byte[] bytes = inetAddress.getAddress();
        if (inetAddress instanceof Inet4Address
            && (ByteBuffer.wrap(bytes).getInt() & CGNAT_MASK) == CGNAT_PREFIX) {
            return null;
        }
        // Unique local addresses fc00::/7, isSiteLocalAddress only covers the deprecated fec0::/10
        if (inetAddress instanceof Inet6Address && (bytes[0] & 0xFE) == 0xFC) {
            return null;
        }
        return inetAddress;
    }

}
