package org.mycore.waf;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import org.mycore.common.MCRTestCase;
import org.mycore.waf.suspicion.GeoIPLookup;
import org.mycore.waf.suspicion.SuspicionList;

public class WAFSuspicionRulesTest extends MCRTestCase {

    private static final String CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        + "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

    private static final String CHROME_LINUX = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        + "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

    private static final String CHROME_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) "
        + "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.0.0 Mobile/15E148 Safari/604.1";

    private static final String FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) "
        + "Gecko/20100101 Firefox/158.0";

    // 2026-10-19 10:54 UTC, Europe/Berlin is in daylight saving time (UTC+2)
    private static final long TIMESTAMP = 1792400043828L;

    private WAFSuspicionRules defaultRules;

    private String userAgentHeader;

    private String acceptLanguageHeader;

    private String remoteAddress;

    private GeoIPLookup geoIP;

    @Before
    public void loadDefaultRules() {
        SuspicionList defaultList = WAFSuspicionRules.loadSuspicionList("waf/default-suspicion-rules.xml");
        assertNotNull("default rules should be loadable from the classpath", defaultList);
        defaultRules = new WAFSuspicionRules(List.of(defaultList));
        userAgentHeader = null;
        acceptLanguageHeader = "de-DE,de;q=0.9";
        remoteAddress = "192.0.2.10";
        geoIP = GeoIPLookup.NONE;
    }

    private HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("User-Agent")).thenReturn(userAgentHeader);
        when(request.getHeader("Accept-Language")).thenReturn(acceptLanguageHeader);
        when(request.getHeaders("Accept-Language")).thenReturn(acceptLanguageHeader == null
            ? Collections.emptyEnumeration()
            : Collections.enumeration(List.of(acceptLanguageHeader)));
        return request;
    }

    private static JsonObject browser(String userAgent, String platform, String timezone, int timezoneOffset,
        String screenResolution, int hardwareConcurrency, String... languages) {
        JsonObject info = new JsonObject();
        info.addProperty("userAgent", userAgent);
        info.addProperty("language", languages[0]);
        JsonArray languageArray = new JsonArray();
        for (String language : languages) {
            languageArray.add(language);
        }
        info.add("languages", languageArray);
        info.addProperty("platform", platform);
        info.addProperty("hardwareConcurrency", hardwareConcurrency);
        info.addProperty("deviceMemory", 16);
        info.addProperty("screenResolution", screenResolution);
        info.addProperty("colorDepth", 24);
        info.addProperty("timezone", timezone);
        info.addProperty("timezoneOffset", timezoneOffset);
        JsonArray plugins = new JsonArray();
        plugins.add("PDF Viewer");
        plugins.add("Chrome PDF Viewer");
        info.add("plugins", plugins);
        info.addProperty("webdriver", false);
        info.addProperty("headless", false);
        info.addProperty("cookieEnabled", true);
        info.addProperty("touchSupport", false);
        info.addProperty("timestamp", TIMESTAMP);
        return info;
    }

    private List<String> find(WAFSuspicionRules rules, String information, String address, String redirectURL) {
        return rules.findMatchingRules(request(), information, address, redirectURL, geoIP);
    }

    private List<String> evaluate(WAFSuspicionRules rules, JsonObject info) {
        if (userAgentHeader == null) {
            userAgentHeader = info.get("userAgent").getAsString();
        }
        return find(rules, info.toString(), remoteAddress, "/receive/mir_mods_00000001");
    }

    @Test
    public void regularBrowserIsNotSuspicious() {
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 12, "de-DE", "de");
        assertEquals(List.of(), evaluate(defaultRules, info));
    }

    @Test
    public void regularFirefoxWithoutDeviceMemoryIsNotSuspicious() {
        JsonObject info = browser(FIREFOX_WINDOWS, "Win32", "Europe/Berlin", -120, "1536x864", 8, "de");
        info.remove("deviceMemory");
        assertEquals(List.of(), evaluate(defaultRules, info));
    }

    @Test
    public void chineseUserIsNotSuspicious() {
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Asia/Shanghai", -480, "1920x1080", 16, "zh-CN", "zh");
        assertEquals(List.of(), evaluate(defaultRules, info));
    }

    @Test
    public void shanghaiServerBotIsSuspicious() {
        JsonObject info = browser(CHROME_LINUX, "Linux x86_64", "Asia/Shanghai", -480, "1280x1024", 192, "en-US");
        assertEquals(List.of("excessive-hardware-concurrency", "unusual-screen-resolution",
            "chinese-timezone-without-chinese-language"), evaluate(defaultRules, info));
    }

    @Test
    public void windowsUserAgentOnLinuxIsSuspicious() {
        JsonObject info = browser(CHROME_WINDOWS, "Linux x86_64", "UTC", 0, "800x600", 4, "en-US", "en");
        info.addProperty("deviceMemory", 0.5);
        assertEquals(List.of("unusual-screen-resolution", "missing-timezone", "user-agent-platform-mismatch",
            "low-device-memory"), evaluate(defaultRules, info));
    }

    @Test
    public void iPhoneUserAgentOnLinuxIsSuspicious() {
        JsonObject info = browser(CHROME_IPHONE, "Linux x86_64", "Europe/Berlin", -120, "375x812", 64, "de-DE");
        info.add("plugins", new JsonArray());
        assertEquals(List.of("user-agent-platform-mismatch"), evaluate(defaultRules, info));
    }

    @Test
    public void desktopBrowserWithoutPluginsIsSuspicious() {
        JsonObject info = browser(CHROME_LINUX, "Linux x86_64", "America/New_York", 240, "1920x1080", 640, "en-US");
        info.add("plugins", new JsonArray());
        assertEquals(List.of("excessive-hardware-concurrency", "desktop-browser-without-plugins"),
            evaluate(defaultRules, info));
    }

    @Test
    public void unknownTimezoneIsSuspicious() {
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Etc/Unknown", 0, "1920x1080", 8, "zh-CN");
        // Etc/Unknown is not known to the JVM, so the offset cannot be checked
        assertEquals(List.of("missing-timezone"), evaluate(defaultRules, info));
    }

    @Test
    public void fakedTimezoneIsSuspicious() {
        // Timezone faked to Berlin, but the offset still belongs to New York
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", 240, "1920x1080", 8, "de-DE");
        assertEquals(List.of("timezone-offset-mismatch"), evaluate(defaultRules, info));
    }

    @Test
    public void missingTimezoneIsSuspicious() {
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 8, "de-DE");
        info.remove("timezone");
        assertEquals(List.of("missing-timezone"), evaluate(defaultRules, info));
    }

    @Test
    public void differentUserAgentHeaderIsSuspicious() {
        userAgentHeader = FIREFOX_WINDOWS;
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 8, "de-DE");
        assertEquals(List.of("user-agent-header-mismatch"), evaluate(defaultRules, info));
    }

    @Test
    public void missingAcceptLanguageIsSuspicious() {
        acceptLanguageHeader = null;
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 8, "de-DE");
        assertEquals(List.of("missing-accept-language"), evaluate(defaultRules, info));
    }

    @Test
    public void remoteAddressAndRedirectURLAreEvaluated() {
        SuspicionList testList = WAFSuspicionRules.loadSuspicionList("waf/suspicion-list-test.xml");
        assertNotNull(testList);
        WAFSuspicionRules rules = new WAFSuspicionRules(List.of(testList));
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 8, "en-US", "en");
        userAgentHeader = CHROME_WINDOWS;

        assertEquals(List.of(), find(rules, info.toString(), "192.0.2.10", "/"));
        assertEquals(List.of("datacenter"),
            find(rules, info.toString(), "203.0.113.99", "/"));
        assertEquals(List.of("datacenter"),
            find(rules, info.toString(), "198.51.100.7", "/"));
        assertEquals(List.of("search-from-english-only"),
            find(rules, info.toString(), "192.0.2.10", "/servlets/solr/find?q=x"));

        JsonObject german = browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 8, "en-US", "de");
        assertEquals(List.of(),
            find(rules, german.toString(), "192.0.2.10", "/servlets/solr/find?q=x"));
    }

    @Test
    public void unparsableInformationIsSuspicious() {
        assertTrue(find(defaultRules, "not json", "192.0.2.10", "/")
            .contains("unparsable-client-information"));
    }

    @Test
    public void noRulesMeansNotSuspicious() {
        WAFSuspicionRules rules = new WAFSuspicionRules(List.of());
        assertEquals(List.of(), find(rules, "not json", "192.0.2.10", "/"));
    }

    @Test
    public void rangeWithoutBoundsIsRejected() {
        assertNull(WAFSuspicionRules.loadSuspicionList("waf/suspicion-list-invalid-range.xml"));
    }

    @Test
    public void unknownElementIsRejectedBySchema() {
        assertNull(WAFSuspicionRules.loadSuspicionList("waf/suspicion-list-unknown-element.xml"));
    }

    private void geoIP(String country, long asn) {
        geoIP = (database, address) -> switch (database) {
            case "country" -> Map.of("country_code", country);
            case "asn" -> Map.of("autonomous_system_number", asn, "autonomous_system_organization", "Test");
            default -> null;
        };
    }

    private JsonObject regularBrowser() {
        return browser(CHROME_WINDOWS, "Win32", "Europe/Berlin", -120, "1920x1080", 12, "de-DE", "de");
    }

    @Test
    public void europeanResidentialAddressIsNotSuspicious() {
        geoIP("DE", 3320);
        assertEquals(List.of(), evaluate(defaultRules, regularBrowser()));
    }

    @Test
    public void addressOutsideOfEuropeIsSuspicious() {
        geoIP("CN", 4134);
        assertEquals(List.of("outside-europe"), evaluate(defaultRules, regularBrowser()));
    }

    @Test
    public void cloudProviderIsSuspicious() {
        geoIP("DE", 16509);
        assertEquals(List.of("cloud-provider"), evaluate(defaultRules, regularBrowser()));
    }

    @Test
    public void unknownAddressDoesNotMatchNegatedGeoIPRules() {
        // Database missing or private address: "not in Europe" must not match
        geoIP = GeoIPLookup.NONE;
        assertEquals(List.of(), evaluate(defaultRules, regularBrowser()));
    }

    @Test
    public void nestedCountryLayoutIsSupported() {
        geoIP = (database, address) -> "country".equals(database)
            ? Map.of("country", Map.of("iso_code", "US"))
            : null;
        assertEquals(List.of("outside-europe"), evaluate(defaultRules, regularBrowser()));
    }

    @Test
    public void unknownTimezoneIdIsNoMismatch() {
        // Newer IANA names may be unknown to an older JDK
        JsonObject info = regularBrowser();
        info.addProperty("timezone", "Europe/Neverland");
        assertEquals(List.of(), evaluate(defaultRules, info));
    }

    @Test
    public void undeterminableFactDoesNotDependOnOrder() {
        SuspicionList list = WAFSuspicionRules.loadSuspicionList("waf/suspicion-list-geoip-order.xml");
        assertNotNull(list);
        WAFSuspicionRules rules = new WAFSuspicionRules(List.of(list));
        JsonObject info = browser(CHROME_WINDOWS, "Win32", "Asia/Shanghai", -480, "1920x1080", 8, "zh-CN");
        userAgentHeader = CHROME_WINDOWS;

        // Without GeoIP data no rule may match, whatever the order of the facts
        assertEquals(List.of(), find(rules, info.toString(), "192.0.2.10", "/"));

        geoIP("CN", 4134);
        assertEquals(List.of("or-value-first", "or-country-first", "not-and"),
            find(rules, info.toString(), "192.0.2.10", "/"));
    }

    @Test
    public void referencedGeoIPDatabasesAreCollected() {
        assertEquals(Set.of("asn", "country"), defaultRules.getGeoIPDatabases());
        SuspicionList testList = WAFSuspicionRules.loadSuspicionList("waf/suspicion-list-test.xml");
        assertEquals(Set.of(), new WAFSuspicionRules(List.of(testList)).getGeoIPDatabases());
    }

}
