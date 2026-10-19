package org.mycore.waf;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.mycore.common.MCRClassTools;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.services.i18n.MCRTranslation;
import org.mycore.util.concurrent.MCRTransactionableRunnable;

/**
 * Service for rendering WAF HTML templates with i18n support.
 * Template files are loaded once from the classpath and cached.
 * Placeholders in the form {{key}} are replaced either with translated strings
 * (via MCRTranslation) or with explicitly provided values.
 */
public class WAFTemplateService {

  private static final String CONFIG_CHALLENGE_HTML = "MCR.WAF.ChallengeHtml";
  private static final String CONFIG_CHALLENGE_FAIL_HTML = "MCR.WAF.ChallengeFailHtml";
  private static final String CONFIG_CHALLENGE_SCRIPT = "MCR.WAF.ChallengeScript";
  private static final String CONFIG_INTERACTION_HTML = "MCR.WAF.InteractionHtml";
  private static final String CONFIG_INTERACTION_SCRIPT = "MCR.WAF.InteractionScript";

  private static final String DEFAULT_CHALLENGE_HTML = "pow-challenge.html";
  private static final String DEFAULT_CHALLENGE_FAIL_HTML = "pow-challenge-fail.html";
  private static final String DEFAULT_CHALLENGE_SCRIPT = "pow-challenge.js";
  private static final String DEFAULT_INTERACTION_HTML = "pow-interaction.html";
  private static final String DEFAULT_INTERACTION_SCRIPT = "pow-interaction.js";

  // Texts that are drawn on the canvas of the interaction challenge, passed to the script as JSON
  private static final List<String> INTERACTION_TEXT_KEYS = List.of("waf.interaction.heading",
      "waf.interaction.description", "waf.interaction.label", "waf.interaction.verifying");

  private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\{\\{([^}]+)\\}\\}");

  private final String challengeHtml;
  private final String challengeFailHtml;
  private final String challengeScript;
  private final String interactionHtml;
  private final String interactionScript;

  // HTML escaping is enabled by default, so the JSON can be embedded in a script element safely
  private final Gson gson = new Gson();

  public WAFTemplateService() {
    String challengePath = MCRConfiguration2.getString(CONFIG_CHALLENGE_HTML)
        .orElse(DEFAULT_CHALLENGE_HTML);
    String challengeFailPath = MCRConfiguration2.getString(CONFIG_CHALLENGE_FAIL_HTML)
        .orElse(DEFAULT_CHALLENGE_FAIL_HTML);
    String challengeScriptPath = MCRConfiguration2.getString(CONFIG_CHALLENGE_SCRIPT)
        .orElse(DEFAULT_CHALLENGE_SCRIPT);
    this.challengeHtml = loadHtml(challengePath);
    this.challengeFailHtml = loadHtml(challengeFailPath);
    this.challengeScript = loadHtml(challengeScriptPath);
    this.interactionHtml = loadHtml(MCRConfiguration2.getString(CONFIG_INTERACTION_HTML)
        .orElse(DEFAULT_INTERACTION_HTML));
    this.interactionScript = loadHtml(MCRConfiguration2.getString(CONFIG_INTERACTION_SCRIPT)
        .orElse(DEFAULT_INTERACTION_SCRIPT));

    // initialize MCRTranslation once
    new MCRTransactionableRunnable(new Runnable() {
      @Override
      public void run() {
        MCRTranslation.translate("Test");
      }
    }).run();
  }

  /**
   * Renders the challenge page for the given locale.
   *
   * @param locale     the locale to use for translations
   * @param extraValues additional placeholder values (e.g. "pow_challenge_token")
   * @return the rendered HTML string
   */
  public String renderChallenge(Locale locale, Map<String, String> extraValues) {
    // Render the JS first so its placeholders (i18n keys + pow_challenge_token) are resolved
    String renderedScript = render(challengeScript, locale, extraValues);

    Map<String, String> htmlValues = new HashMap<>();
    htmlValues.put("lang", locale.getLanguage());
    htmlValues.put("pow_challenge_script", renderedScript);
    return render(challengeHtml, locale, htmlValues);
  }

  /**
   * Renders the interaction challenge page for the given locale. The configuration is passed to
   * the script as JSON via the {{interaction_config}} placeholder, extended by an {@code i18n}
   * object with the texts drawn on the canvas.
   *
   * @param locale the locale to use for translations
   * @param config the configuration of the interaction challenge (token, checkbox position, ...)
   * @return the rendered HTML string
   */
  public String renderInteraction(Locale locale, JsonObject config) {
    JsonObject texts = new JsonObject();
    for (String key : INTERACTION_TEXT_KEYS) {
      texts.addProperty(key.substring(key.lastIndexOf('.') + 1), translate(key, locale));
    }
    JsonObject scriptConfig = config.deepCopy();
    scriptConfig.add("i18n", texts);
    String renderedScript = render(interactionScript, locale,
        Map.of("interaction_config", gson.toJson(scriptConfig)));

    Map<String, String> htmlValues = new HashMap<>();
    htmlValues.put("lang", locale.getLanguage());
    htmlValues.put("interaction_script", renderedScript);
    return render(interactionHtml, locale, htmlValues);
  }

  /**
   * Renders the failure page for the given locale.
   *
   * @param locale the locale to use for translations
   * @return the rendered HTML string
   */
  public String renderFailPage(Locale locale) {
    return render(challengeFailHtml, locale, Map.of("lang", locale.getLanguage()));
  }

  private String render(String template, Locale locale, Map<String, String> extraValues) {
    Matcher matcher = PLACEHOLDER_PATTERN.matcher(template);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      String key = matcher.group(1);
      String replacement = extraValues.containsKey(key)
          ? extraValues.get(key)
          : translate(key, locale);
      matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  private static String translate(String key, Locale locale) {
    try {
      return MCRTranslation.translateToLocale(key, locale);
    } catch (Exception e) {
      return key;
    }
  }

  static String loadHtml(String resource) {
    try (InputStream is = MCRClassTools.getClassLoader().getResourceAsStream(resource)) {
      if (is == null) {
        throw new RuntimeException("WAF template resource not found on classpath: " + resource);
      }
      return new String(is.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new RuntimeException("Failed to load WAF template resource: " + resource, e);
    }
  }
}
