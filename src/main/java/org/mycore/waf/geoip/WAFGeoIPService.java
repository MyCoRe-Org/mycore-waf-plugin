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
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.common.config.MCRConfigurationException;
import org.mycore.common.events.MCRShutdownHandler;
import org.mycore.waf.suspicion.GeoIPLookup;

/**
 * Provides the GeoIP databases used by the suspicion rules, configured in
 * {@code MCR.WAF.GeoIP.Database.<name>.*} independent of the suspicion rules. A database with a
 * {@code URL} is downloaded and kept up to date, a database without URL is only read from its local
 * file. No URL is configured by default, so nothing is downloaded. The files are stored in
 * {@code MCR.WAF.GeoIP.Directory} and updated in a background thread every
 * {@code MCR.WAF.GeoIP.UpdateIntervalHours} hours. While a database is not available, for example
 * because the first download failed, the update is retried every
 * {@code MCR.WAF.GeoIP.RetryIntervalMinutes} minutes. Until then, GeoIP facts cannot be evaluated
 * and rules using them do not match.
 * <p>
 * Private, loopback, link local and shared (CGNAT) addresses are never looked up, so GeoIP rules
 * never match local test systems or clients in a VPN with private addresses.
 */
public class WAFGeoIPService implements GeoIPLookup {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String CONFIG_PREFIX = "MCR.WAF.GeoIP.";
    private static final String CONFIG_DIRECTORY = CONFIG_PREFIX + "Directory";
    private static final String CONFIG_DATABASE_PREFIX = CONFIG_PREFIX + "Database.";
    private static final String CONFIG_UPDATE_INTERVAL_HOURS = CONFIG_PREFIX + "UpdateIntervalHours";
    private static final String CONFIG_RETRY_INTERVAL_MINUTES = CONFIG_PREFIX + "RetryIntervalMinutes";

    private static final int DEFAULT_UPDATE_INTERVAL_HOURS = 24;
    private static final int DEFAULT_RETRY_INTERVAL_MINUTES = 15;

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(30);

    // IP literals only, so that InetAddress.getByName never performs a DNS lookup: a dotted quad for
    // IPv4, hex digits with at least one colon for IPv6. Host names never contain a colon.
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern IPV6_LITERAL = Pattern.compile("[0-9a-fA-F.]*:[0-9a-fA-F:.]*");

    // 100.64.0.0/10, shared address space for carrier grade NAT (RFC 6598)
    private static final int CGNAT_PREFIX = 0x64400000;
    private static final int CGNAT_MASK = 0xFFC00000;

    private final Map<String, GeoIPDatabase> databases;

    private final Set<String> warnedDatabases = ConcurrentHashMap.newKeySet();

    private ScheduledExecutorService scheduler;

    private Duration updateInterval;

    private Duration retryInterval;

    private HttpClient client;

    /**
     * Creates a service for the given databases without starting the update thread.
     *
     * @param databases the databases
     */
    public WAFGeoIPService(List<GeoIPDatabase> databases) {
        this(databases, Duration.ofHours(DEFAULT_UPDATE_INTERVAL_HOURS),
            Duration.ofMinutes(DEFAULT_RETRY_INTERVAL_MINUTES));
    }

    WAFGeoIPService(List<GeoIPDatabase> databases, Duration updateInterval, Duration retryInterval) {
        this.databases = new LinkedHashMap<>();
        databases.forEach(database -> this.databases.put(database.getName(), database));
        this.updateInterval = updateInterval;
        this.retryInterval = retryInterval;
    }

    /**
     * Creates the service from the configuration, loads the local database files and starts the
     * background thread that downloads and updates the databases with a URL.
     *
     * @return the started service, or a service without databases if none are configured
     */
    public static WAFGeoIPService start() {
        List<GeoIPDatabase> databases = loadConfiguration();
        WAFGeoIPService service = new WAFGeoIPService(databases);
        // Databases without URL are only read from the local file, which is done once
        databases.forEach(GeoIPDatabase::load);
        if (databases.stream().anyMatch(GeoIPDatabase::hasURL)) {
            service.startUpdates(
                Duration.ofHours(MCRConfiguration2.getInt(CONFIG_UPDATE_INTERVAL_HOURS)
                    .orElse(DEFAULT_UPDATE_INTERVAL_HOURS)),
                Duration.ofMinutes(MCRConfiguration2.getInt(CONFIG_RETRY_INTERVAL_MINUTES)
                    .orElse(DEFAULT_RETRY_INTERVAL_MINUTES)));
        }
        return service;
    }

    /**
     * Reads the databases from the configuration. Every name with a property
     * {@code MCR.WAF.GeoIP.Database.<name>.*} is a database, databases without {@code File} are
     * ignored.
     *
     * @return the configured databases, empty if there are none or the directory is not set
     */
    static List<GeoIPDatabase> loadConfiguration() {
        List<GeoIPDatabase> databases = new ArrayList<>();
        // Every name with a property MCR.WAF.GeoIP.Database.<name>.* is a database
        Set<String> databaseNames = MCRConfiguration2.getSubPropertiesMap(CONFIG_DATABASE_PREFIX).keySet().stream()
            .map(key -> key.substring(0, key.indexOf('.') < 0 ? key.length() : key.indexOf('.')))
            .collect(Collectors.toCollection(TreeSet::new));
        String disabledReason = getDisabledReason();
        if (disabledReason != null) {
            LOGGER.info("GeoIP is disabled: {}", disabledReason);
            return databases;
        }
        String directory = MCRConfiguration2.getStringOrThrow(CONFIG_DIRECTORY);
        int intervalHours = MCRConfiguration2.getInt(CONFIG_UPDATE_INTERVAL_HOURS)
            .orElse(DEFAULT_UPDATE_INTERVAL_HOURS);
        for (String name : databaseNames) {
            String prefix = CONFIG_DATABASE_PREFIX + name + ".";
            Optional<String> fileName = MCRConfiguration2.getString(prefix + "File").filter(value -> !value.isBlank());
            if (fileName.isEmpty()) {
                LOGGER.error("GeoIP database '{}' has no {}File, ignoring it", name, prefix);
                continue;
            }
            URI url = MCRConfiguration2.getString(prefix + "URL").filter(value -> !value.isBlank())
                .map(URI::create).orElse(null);
            URI checksumURL = MCRConfiguration2.getString(prefix + "ChecksumURL").filter(value -> !value.isBlank())
                .map(URI::create).orElse(null);
            databases.add(new GeoIPDatabase(name, Path.of(directory).resolve(fileName.get()), url,
                checksumURL, Duration.ofHours(intervalHours)));
        }
        return databases;
    }

    /**
     * Checks the directory of the databases.
     *
     * @return why GeoIP is disabled, or null if the directory is configured
     */
    static String getDisabledReason() {
        try {
            if (MCRConfiguration2.getString(CONFIG_DIRECTORY).filter(value -> !value.isBlank()).isEmpty()) {
                return CONFIG_DIRECTORY + " is empty";
            }
            return null;
        } catch (MCRConfigurationException e) {
            return CONFIG_DIRECTORY + " cannot be resolved: " + e.getMessage();
        }
    }

    private void startUpdates(Duration updateInterval, Duration retryInterval) {
        this.updateInterval = updateInterval;
        this.retryInterval = retryInterval;
        this.client = HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "WAF GeoIP Update");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.execute(this::updateAndReschedule);
        MCRShutdownHandler.getInstance().addCloseable(this::stop);
    }

    private void updateAndReschedule() {
        updateAll();
        if (Thread.currentThread().isInterrupted() || scheduler.isShutdown()) {
            return;
        }
        Duration delay = nextDelay();
        LOGGER.debug("Next GeoIP update check in {}", delay);
        scheduler.schedule(this::updateAndReschedule, delay.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * Returns the delay until the next update check: the retry interval while a database could not
     * be loaded yet, for example because the first download failed, the update interval otherwise.
     */
    Duration nextDelay() {
        boolean allAvailable = databases.values().stream()
            .filter(GeoIPDatabase::hasURL)
            .allMatch(GeoIPDatabase::isAvailable);
        return allAvailable ? updateInterval : retryInterval;
    }

    private void updateAll() {
        for (GeoIPDatabase database : databases.values()) {
            if (!database.hasURL()) {
                continue;
            }
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

    @Override
    public Map<String, Object> lookup(String database, String address) {
        GeoIPDatabase geoIPDatabase = databases.get(database);
        if (geoIPDatabase == null) {
            // The reason is only determined for the first lookup of the database, it is logged once
            String disabledReason = warnedDatabases.contains(database) ? null : getDisabledReason();
            if (disabledReason != null) {
                warnOnce(database, "GeoIP database '{}' is used by a suspicion rule, but GeoIP is disabled: {}. "
                    + "Rules using it never match.", database, disabledReason);
            } else {
                warnOnce(database, "GeoIP database '{}' is used by a suspicion rule, but not configured. Rules using "
                    + "it never match. Set {}{}.File and {}{}.URL.", database, CONFIG_DATABASE_PREFIX, database,
                    CONFIG_DATABASE_PREFIX, database);
            }
            return null;
        }
        if (!geoIPDatabase.hasURL() && !geoIPDatabase.isAvailable()) {
            warnOnce(database, "GeoIP database '{}' is used by a suspicion rule, but has no URL and no local file. "
                + "Rules using it never match. Set {}{}.URL or place the file and restart.", database,
                CONFIG_DATABASE_PREFIX, database);
            return null;
        }
        if (address == null) {
            return null;
        }
        InetAddress inetAddress = parsePublicAddress(address);
        return inetAddress == null ? null : geoIPDatabase.lookup(inetAddress);
    }

    /**
     * Logs a warning only once per database, the lookup runs for every solved challenge.
     */
    private void warnOnce(String database, String message, Object... parameters) {
        if (warnedDatabases.add(database)) {
            LOGGER.warn(message, parameters);
        }
    }

    /**
     * Parses an IP literal and checks that it is a public address.
     *
     * @param address the IP address
     * @return the parsed address, or null if it is no IP literal or not public
     */
    static InetAddress parsePublicAddress(String address) {
        if (!IPV4_LITERAL.matcher(address).matches() && !IPV6_LITERAL.matcher(address).matches()) {
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
