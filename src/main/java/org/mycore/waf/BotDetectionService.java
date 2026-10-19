package org.mycore.waf;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Service for detecting bots and automated tools.
 */
public class BotDetectionService {

  private static final String[] BOT_USER_AGENT_PATTERNS = {
      "bot", "crawler", "spider", "scraper",
      "curl", "wget", "python", "java/", "go-http-client",
      "headless", "phantomjs", "selenium", "webdriver",
      "scrapy", "axios", "node-fetch", "postman"
  };

  private static final Pattern SCREEN_RESOLUTION_PATTERN = Pattern.compile("\\d+x\\d+");

  private final Gson gson = new Gson();

  /**
   * Checks if the request appears to be from a bot based on User-Agent and client information.
   *
   * @param request the HTTP request
   * @param clientInformation JSON string with client information from JavaScript
   * @return true if the request appears legitimate, false if it's likely a bot
   */
  public boolean checkBotInformation(HttpServletRequest request, String clientInformation) {
    // Check User-Agent header for known bots
    if (!checkUserAgent(request)) {
      return false;
    }

    // Check client information gathered by JavaScript
    if (!checkClientInformation(clientInformation)) {
      return false;
    }

    return true;
  }

  private boolean checkUserAgent(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    if (userAgent == null || userAgent.isEmpty()) {
      return false; // No user agent = suspicious
    }

    String userAgentLower = userAgent.toLowerCase(Locale.ROOT);
    for (String pattern : BOT_USER_AGENT_PATTERNS) {
      if (userAgentLower.contains(pattern)) {
        return false; // Known bot detected
      }
    }

    return true;
  }

  /**
   * Checks the client information gathered by the challenge page JavaScript.
   * <p>
   * Every field that is checked must be present. A missing field is treated like an invalid one,
   * because a script that solves the Proof of Work without a browser can simply leave out all
   * fields that would reveal it.
   *
   * @param clientInformation JSON string with client information from JavaScript
   * @return true if the information looks like it was gathered by a real browser, false otherwise
   */
  boolean checkClientInformation(String clientInformation) {
    if (clientInformation == null || clientInformation.isEmpty()) {
      return false; // No client info = suspicious
    }

    try {
      JsonObject json = gson.fromJson(clientInformation, JsonObject.class);
      if (json == null) {
        return false;
      }

      // Check for headless browsers (the challenge page also sets this if webdriver is true)
      if (!json.has("headless") || json.get("headless").getAsBoolean()) {
        return false;
      }

      // Check for webdriver, older browsers do not define navigator.webdriver at all
      if (json.has("webdriver") && !json.get("webdriver").isJsonNull()
          && json.get("webdriver").getAsBoolean()) {
        return false; // Selenium/WebDriver detected
      }

      // Check for cookies disabled
      if (!json.has("cookieEnabled") || !json.get("cookieEnabled").getAsBoolean()) {
        return false; // Cookies disabled, the WAF cookie could not be set anyway
      }

      // Check hardware concurrency (should be at least 1)
      if (!json.has("hardwareConcurrency") || json.get("hardwareConcurrency").getAsInt() < 1) {
        return false; // Invalid hardware info
      }

      // Check screen resolution (should be WIDTHxHEIGHT and not 0x0)
      if (!json.has("screenResolution")) {
        return false;
      }
      String screenResolution = json.get("screenResolution").getAsString();
      if (!SCREEN_RESOLUTION_PATTERN.matcher(screenResolution).matches() || "0x0".equals(screenResolution)) {
        return false; // Invalid screen resolution
      }

      // Check color depth (should be > 0)
      if (!json.has("colorDepth") || json.get("colorDepth").getAsInt() <= 0) {
        return false; // Invalid color depth
      }

      // Check if languages array is empty
      if (!json.has("languages") || json.get("languages").getAsJsonArray().isEmpty()) {
        return false; // No languages = suspicious
      }

      return true;

    } catch (JsonSyntaxException | IllegalStateException | ClassCastException | UnsupportedOperationException
        | NumberFormatException e) {
      // If we can't parse the information, reject it
      return false;
    }
  }
}
