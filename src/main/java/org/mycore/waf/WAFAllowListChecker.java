package org.mycore.waf;

import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.MCRCache;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.frontend.MCRFrontendUtil;

/**
 * Handles allow list checks for IP addresses and paths.
 */
public class WAFAllowListChecker {

  private static final Logger LOGGER = LogManager.getLogger();

  private static final String CONFIG_ALLOWED_IPS = "MCR.WAF.AllowedIPs";
  private static final String CONFIG_ALLOWED_PATHS = "MCR.WAF.AllowedPaths";
  private static final String CONFIG_KNOWN_BOT_REVERSE_DNS = "MCR.WAF.KnownBotReverseDNS";
  private static final String CONFIG_KNOWN_BOT_USER_AGENTS = "MCR.WAF.KnownBotUserAgents";
  private static final String CONFIG_VERIFY_REVERSE_DNS = "MCR.WAF.VerifyReverseDNS";
  private static final String CONFIG_DNS_CACHE_CAPACITY = "MCR.WAF.DNSCacheCapacity";
  private static final String CONFIG_DNS_CACHE_TTL_MINUTES = "MCR.WAF.DNSCacheTTLMinutes";
  private static final String CONFIG_SUB_RESOURCE_DESTINATIONS = "MCR.WAF.SubResource.AllowedDestinations";
  private static final String CONFIG_SUB_RESOURCE_PATHS = "MCR.WAF.SubResource.AllowedPaths";

  private static final String HEADER_SEC_FETCH_DEST = "Sec-Fetch-Dest";

  private static final int DEFAULT_DNS_CACHE_CAPACITY = 1000;
  private static final int DEFAULT_DNS_CACHE_TTL_MINUTES = 60;

  // Cached for IPs without a verified hostname, MCRCache does not accept null values
  private static final String NO_VERIFIED_HOSTNAME = "";

  private final List<IPRange> allowedIPRanges;
  private final List<Pattern> allowedPathPatterns;
  private final List<Pattern> knownBotReverseDNSPatterns;
  private final List<String> knownBotUserAgents;
  private final boolean verifyReverseDNS;
  private final List<String> allowedSubResourceDestinations;
  private final List<Pattern> allowedSubResourcePathPatterns;

  // Cache for reverse DNS lookups (IP -> verified hostname or NO_VERIFIED_HOSTNAME), bounded with TTL via MCRCache
  private final MCRCache<String, String> reverseDNSCache;

  private final long dnsCacheTTLMillis;

  // Reverse DNS lookups currently in progress, so concurrent requests from one IP share a lookup
  private final ConcurrentHashMap<String, CompletableFuture<String>> pendingDNSLookups = new ConcurrentHashMap<>();

  public WAFAllowListChecker() {
    this.allowedIPRanges = loadAllowedIPs();
    this.allowedPathPatterns = loadAllowedPaths();
    this.knownBotReverseDNSPatterns = loadKnownBotReverseDNS();
    this.knownBotUserAgents = loadKnownBotUserAgents();
    this.verifyReverseDNS = MCRConfiguration2.getBoolean(CONFIG_VERIFY_REVERSE_DNS).orElse(true);
    this.allowedSubResourceDestinations = loadAllowedSubResourceDestinations();
    this.allowedSubResourcePathPatterns = loadPatterns(CONFIG_SUB_RESOURCE_PATHS, "sub resource path");
    int capacity = MCRConfiguration2.getInt(CONFIG_DNS_CACHE_CAPACITY).orElse(DEFAULT_DNS_CACHE_CAPACITY);
    this.reverseDNSCache = new MCRCache<>(capacity, "WAF Reverse DNS");
    int ttlMinutes = MCRConfiguration2.getInt(CONFIG_DNS_CACHE_TTL_MINUTES).orElse(DEFAULT_DNS_CACHE_TTL_MINUTES);
    this.dnsCacheTTLMillis = ttlMinutes * 60_000L;
  }

  private List<IPRange> loadAllowedIPs() {
    List<IPRange> ranges = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_ALLOWED_IPS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] ips = config.get().split(",");
      for (String ip : ips) {
        ip = ip.trim();
        if (!ip.isEmpty()) {
          try {
            ranges.add(IPRange.parse(ip));
            LOGGER.info("Added IP range to allow list: {}", ip);
          } catch (IllegalArgumentException e) {
            LOGGER.error("Invalid IP range in configuration: {}", ip, e);
          }
        }
      }
    }

    return ranges;
  }

  private List<Pattern> loadAllowedPaths() {
    return loadPatterns(CONFIG_ALLOWED_PATHS, "path");
  }

  private List<Pattern> loadPatterns(String property, String description) {
    List<Pattern> patterns = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(property);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] paths = config.get().split(",");
      for (String path : paths) {
        path = path.trim();
        if (!path.isEmpty()) {
          try {
            patterns.add(Pattern.compile(path));
            LOGGER.info("Added {} pattern to allow list: {}", description, path);
          } catch (Exception e) {
            LOGGER.error("Invalid {} pattern in configuration: {}", description, path, e);
          }
        }
      }
    }

    return patterns;
  }

  private List<String> loadAllowedSubResourceDestinations() {
    List<String> destinations = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_SUB_RESOURCE_DESTINATIONS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] values = config.get().split(",");
      for (String value : values) {
        value = value.trim();
        if (!value.isEmpty()) {
          destinations.add(value.toLowerCase(Locale.ROOT));
          LOGGER.info("Added allowed Sec-Fetch-Dest value: {}", value);
        }
      }
    }

    return destinations;
  }

  private List<Pattern> loadKnownBotReverseDNS() {
    List<Pattern> patterns = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_KNOWN_BOT_REVERSE_DNS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] hostPatterns = config.get().split(",");
      for (String hostPattern : hostPatterns) {
        hostPattern = hostPattern.trim();
        if (!hostPattern.isEmpty()) {
          try {
            // Convert wildcards to regex (e.g., *.googlebot.com -> .*\.googlebot\.com)
            String regex = hostPattern
                .replace(".", "\\.")
                .replace("*", ".*");
            patterns.add(Pattern.compile(regex));
            LOGGER.info("Added known bot reverse DNS pattern: {} (regex: {})", hostPattern, regex);
          } catch (Exception e) {
            LOGGER.error("Invalid known bot reverse DNS pattern in configuration: {}", hostPattern, e);
          }
        }
      }
    }

    return patterns;
  }

  private List<String> loadKnownBotUserAgents() {
    List<String> userAgents = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_KNOWN_BOT_USER_AGENTS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] patterns = config.get().split(",");
      for (String pattern : patterns) {
        pattern = pattern.trim();
        if (!pattern.isEmpty()) {
          userAgents.add(pattern.toLowerCase(Locale.ROOT));
          LOGGER.info("Added known bot user agent pattern: {}", pattern);
        }
      }
    }

    return userAgents;
  }

  /**
   * Checks if the request IP is on the allow list.
   *
   * @param request the HTTP request
   * @return true if the IP is allowed, false otherwise
   */
  public boolean isIPAllowed(HttpServletRequest request) {
    if (allowedIPRanges.isEmpty()) {
      return false;
    }

    String remoteIP = MCRFrontendUtil.getRemoteAddr(request);
    for (IPRange range : allowedIPRanges) {
      if (range.contains(remoteIP)) {
        LOGGER.debug("IP {} is on allow list", remoteIP);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if the request path is on the allow list.
   *
   * @param request the HTTP request
   * @return true if the path is allowed, false otherwise
   */
  public boolean isPathAllowed(HttpServletRequest request) {
    if (allowedPathPatterns.isEmpty()) {
      return false;
    }

    String path = getApplicationRelativePath(request);
    for (Pattern pattern : allowedPathPatterns) {
      if (pattern.matcher(path).matches()) {
        LOGGER.debug("Path {} matches allow list pattern: {}", path, pattern);
        return true;
      }
    }
    return false;
  }

  /**
   * Returns the request path relative to the context path, as decoded and normalized by the
   * servlet container.
   * <p>
   * The raw {@link HttpServletRequest#getRequestURI()} must not be used here: it is neither decoded
   * nor normalized, while the container resolves dot segments and strips path parameters before it
   * dispatches the request. A request like {@code /api/..;/receive/foo} would then match an allow
   * list pattern for {@code /api/.*} but actually be served by {@code /receive/foo}.
   *
   * @param request the HTTP request
   * @return the normalized, context relative path
   */
  static String getApplicationRelativePath(HttpServletRequest request) {
    String servletPath = Objects.toString(request.getServletPath(), "");
    String pathInfo = Objects.toString(request.getPathInfo(), "");
    return servletPath + pathInfo;
  }

  /**
   * Checks if the request comes from a known bot (based on User-Agent) whose reverse DNS
   * hostname matches the configured known bot DNS patterns.
   * The reverse DNS check is only performed if the User-Agent identifies the request
   * as coming from a known bot (e.g., Googlebot, bingbot, Baiduspider, Applebot).
   *
   * @param request the HTTP request
   * @return true if the User-Agent matches a known bot and the reverse DNS is verified, false otherwise
   */
  public boolean isKnownBotAllowedByReverseDNS(HttpServletRequest request) {
    if (knownBotReverseDNSPatterns.isEmpty() || knownBotUserAgents.isEmpty()) {
      return false;
    }

    // Only perform the expensive DNS check if the User-Agent identifies a known bot
    if (!isKnownBotUserAgent(request)) {
      return false;
    }

    String remoteIP = MCRFrontendUtil.getRemoteAddr(request);
    String hostname = getVerifiedHostname(remoteIP);
    if (hostname.isEmpty()) {
      return false;
    }
    return matchesKnownBotReverseDNSPattern(hostname, remoteIP);
  }

  /**
   * Returns the verified reverse DNS hostname of the given IP, using the cache if possible.
   * <p>
   * Failed lookups are cached as well. Otherwise a client that fakes a known bot User-Agent would
   * cause new DNS queries with every single request. Concurrent requests from the same IP share
   * one lookup instead of querying the DNS server in parallel.
   *
   * @param ip the IP address to resolve
   * @return the verified hostname, or an empty string if the IP has no verified hostname
   */
  String getVerifiedHostname(String ip) {
    String cachedHostname = reverseDNSCache.getIfUpToDate(ip, System.currentTimeMillis() - dnsCacheTTLMillis);
    if (cachedHostname != null) {
      return cachedHostname;
    }

    CompletableFuture<String> lookup = new CompletableFuture<>();
    CompletableFuture<String> runningLookup = pendingDNSLookups.putIfAbsent(ip, lookup);
    if (runningLookup != null) {
      return runningLookup.join();
    }

    try {
      String hostname = lookupVerifiedHostname(ip);
      reverseDNSCache.put(ip, hostname);
      lookup.complete(hostname);
      return hostname;
    } catch (RuntimeException e) {
      lookup.completeExceptionally(e);
      throw e;
    } finally {
      pendingDNSLookups.remove(ip, lookup);
    }
  }

  private String lookupVerifiedHostname(String ip) {
    String hostname = performReverseDNSLookup(ip);
    if (hostname == null) {
      LOGGER.debug("No reverse DNS found for IP: {}", ip);
      return NO_VERIFIED_HOSTNAME;
    }

    // Verify with forward DNS lookup if enabled
    if (verifyReverseDNS && !verifyForwardDNS(hostname, ip)) {
      LOGGER.warn("Forward DNS verification failed for hostname: {} (IP: {})", hostname, ip);
      return NO_VERIFIED_HOSTNAME;
    }
    return hostname;
  }

  private boolean isKnownBotUserAgent(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    if (userAgent == null || userAgent.isEmpty()) {
      return false;
    }
    String userAgentLower = userAgent.toLowerCase(Locale.ROOT);
    for (String pattern : knownBotUserAgents) {
      if (userAgentLower.contains(pattern)) {
        LOGGER.debug("User-Agent '{}' matches known bot pattern '{}'", userAgent, pattern);
        return true;
      }
    }
    return false;
  }

  String performReverseDNSLookup(String ip) {
    try {
      InetAddress addr = InetAddress.getByName(ip);
      String hostname = addr.getCanonicalHostName();

      // If getCanonicalHostName returns the IP address, DNS lookup failed
      if (hostname.equals(ip)) {
        return null;
      }

      LOGGER.debug("Reverse DNS lookup for {}: {}", ip, hostname);
      return hostname;

    } catch (UnknownHostException e) {
      LOGGER.debug("Reverse DNS lookup failed for IP: {}", ip, e);
      return null;
    }
  }

  boolean verifyForwardDNS(String hostname, String originalIP) {
    try {
      InetAddress[] addresses = InetAddress.getAllByName(hostname);

      for (InetAddress addr : addresses) {
        if (addr.getHostAddress().equals(originalIP)) {
          LOGGER.debug("Forward DNS verification successful: {} -> {}", hostname, originalIP);
          return true;
        }
      }

      LOGGER.warn("Forward DNS verification failed: {} does not resolve to {}", hostname, originalIP);
      return false;

    } catch (UnknownHostException e) {
      LOGGER.warn("Forward DNS lookup failed for hostname: {}", hostname, e);
      return false;
    }
  }

  private boolean matchesKnownBotReverseDNSPattern(String hostname, String ip) {
    for (Pattern pattern : knownBotReverseDNSPatterns) {
      if (pattern.matcher(hostname).matches()) {
        LOGGER.debug("Reverse DNS {} (IP: {}) matches known bot DNS pattern: {}", hostname, ip, pattern);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if the request is a browser sub resource request that may bypass the WAF challenge.
   * <p>
   * Browsers announce the purpose of a request via the {@code Sec-Fetch-Dest} header. A document
   * that was served without a WAF-PASSED cookie (for example because its path is on the allow
   * list) triggers follow-up requests for stylesheets, scripts, images and fonts. Those requests
   * cannot solve a Proof of Work challenge, so they would fail.
   * <p>
   * Two conditions must be met: the {@code Sec-Fetch-Dest} value must be listed in
   * {@link #CONFIG_SUB_RESOURCE_DESTINATIONS}, and the request must either not be mapped to any
   * servlet (i.e. it is served by the container's default servlet) or its path must match one of
   * the patterns in {@link #CONFIG_SUB_RESOURCE_PATHS}. The second condition keeps dynamically
   * generated content behind the challenge even if a client forges the header.
   *
   * @param request the HTTP request
   * @return true if the request is an allowed sub resource request, false otherwise
   */
  public boolean isAllowedSubResource(HttpServletRequest request) {
    if (allowedSubResourceDestinations.isEmpty()) {
      return false;
    }

    String destination = request.getHeader(HEADER_SEC_FETCH_DEST);
    if (destination == null || destination.isEmpty()) {
      return false;
    }
    if (!allowedSubResourceDestinations.contains(destination.toLowerCase(Locale.ROOT))) {
      LOGGER.debug("Sec-Fetch-Dest {} is not on the allow list", destination);
      return false;
    }

    if (isServedByDefaultServlet(request)) {
      LOGGER.debug("Sub resource request with Sec-Fetch-Dest {} is not mapped to a servlet", destination);
      return true;
    }

    String path = getApplicationRelativePath(request);
    for (Pattern pattern : allowedSubResourcePathPatterns) {
      if (pattern.matcher(path).matches()) {
        LOGGER.debug("Sub resource path {} matches allow list pattern: {}", path, pattern);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks whether the request is handled by the container's default servlet, which means that no
   * servlet mapping matched the request. This is the case for static files that are delivered
   * directly from the web application.
   *
   * @param request the HTTP request
   * @return true if no servlet mapping matched the request, false otherwise
   */
  private boolean isServedByDefaultServlet(HttpServletRequest request) {
    HttpServletMapping mapping = request.getHttpServletMapping();
    return mapping != null && mapping.getMappingMatch() == MappingMatch.DEFAULT;
  }

  /**
   * Checks if either IP, path, reverse DNS, or a browser sub resource request is on the allow list.
   *
   * @param request the HTTP request
   * @return true if IP, path, reverse DNS, or sub resource is allowed, false otherwise
   */
  public boolean isAllowed(HttpServletRequest request) {
    return isIPAllowed(request) || isPathAllowed(request) || isAllowedSubResource(request)
        || isKnownBotAllowedByReverseDNS(request);
  }
}
