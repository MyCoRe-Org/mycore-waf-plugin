package org.mycore.waf;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonObject;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.frontend.MCRFrontendUtil;
import org.mycore.frontend.jersey.MCRJWTUtil;
import org.mycore.waf.geoip.WAFGeoIPService;
import org.mycore.waf.suspicion.GeoIPLookup;

public class DefaultWAFService implements WAFService {

  public static final String WAF_PASSED_CLAIM = "waf_passed";
  public static final String IP_CLAIM = "ip";
  public static final String CHALLENGE_CLAIM = "challenge";
  public static final String DIFFICULTY_CLAIM = "difficulty";
  public static final String REDIRECT_URL_CLAIM = "redirect_url";
  public static final String ATTEMPT_CLAIM = "attempt";
  public static final String STAGE_CLAIM = "stage";
  public static final String BOX_X_CLAIM = "box_x";
  public static final String BOX_Y_CLAIM = "box_y";
  public static final String STAGE_INTERACTION = "interaction";
  public static final String WAF_PASSED_COOKIE_NAME = "WAF-PASSED";

  public static final String POW_SOLUTION_PARAMETER = "pow_solution";
  public static final String CLIENT_INFORMATION_PARAMETER = "information";
  public static final String POW_CHALLENGE_TOKEN_PARAMETER = "pow_challenge_token";
  public static final String REDIRECT_URL_PARAMETER = "redirect_url";
  public static final String ATTEMPT_PARAMETER = "attempt";
  public static final String INTERACTION_TOKEN_PARAMETER = "interaction_token";
  public static final String INTERACTION_EVENTS_PARAMETER = "interaction_events";

  public static final String POW_CHALLENGE_HTML = "pow-challenge.html";
  public static final String POW_CHALLENGE_FAIL_HTML = "pow-challenge-fail.html";

  private static final String CONFIG_ENABLED = "MCR.WAF.Enabled";
  private static final String CONFIG_DIFFICULTY = "MCR.WAF.Difficulty";
  private static final String CONFIG_MAX_ATTEMPTS = "MCR.WAF.MaxAttempts";
  private static final String CONFIG_CHALLENGE_EXPIRY_MINUTES = "MCR.WAF.ChallengeExpiryMinutes";
  private static final String CONFIG_PASSED_TOKEN_EXPIRY_MINUTES = "MCR.WAF.PassedTokenExpiryMinutes";
  private static final String CONFIG_INTERACTION_EXPIRY_MINUTES = "MCR.WAF.Interaction.ExpiryMinutes";
  private static final String CONFIG_INTERACTION_MIN_DURATION = "MCR.WAF.Interaction.MinDurationMillis";
  private static final String CONFIG_INTERACTION_MIN_POINTER_MOVES = "MCR.WAF.Interaction.MinPointerMoves";

  private static final int DEFAULT_DIFFICULTY = 16;
  private static final int DEFAULT_MAX_ATTEMPTS = 3;
  private static final int DEFAULT_CHALLENGE_EXPIRY_MINUTES = 2;
  private static final int DEFAULT_PASSED_TOKEN_EXPIRY_MINUTES = 1440; // 1 day
  private static final int DEFAULT_INTERACTION_EXPIRY_MINUTES = 5;
  private static final int DEFAULT_INTERACTION_MIN_DURATION = 600;
  private static final int DEFAULT_INTERACTION_MIN_POINTER_MOVES = 3;

  // Services
  private final WAFAllowListChecker allowListChecker;
  private final WAFAllowRules allowRules;
  private final WAFSuspicionRules suspicionRules;
  private final GeoIPLookup geoIP;
  private final InteractionValidator interactionValidator;
  private final BotDetectionService botDetectionService;
  private final ProofOfWorkValidator powValidator;
  private final SecureRandom secureRandom;
  private final WAFTemplateService templateService;

  public DefaultWAFService() {
    this.allowListChecker = new WAFAllowListChecker();
    this.allowRules = WAFAllowRules.load();
    this.suspicionRules = WAFSuspicionRules.load();
    // The GeoIP databases are only needed (and downloaded) if suspicion rules are configured
    this.geoIP = suspicionRules.isEmpty() ? GeoIPLookup.NONE : WAFGeoIPService.start();
    this.interactionValidator = new InteractionValidator(
        MCRConfiguration2.getInt(CONFIG_INTERACTION_MIN_DURATION).orElse(DEFAULT_INTERACTION_MIN_DURATION),
        MCRConfiguration2.getInt(CONFIG_INTERACTION_MIN_POINTER_MOVES)
            .orElse(DEFAULT_INTERACTION_MIN_POINTER_MOVES));
    this.botDetectionService = new BotDetectionService();
    this.powValidator = new ProofOfWorkValidator();
    this.secureRandom = new SecureRandom();
    this.templateService = new WAFTemplateService();
  }

  @Override
  public boolean isEnabled() {
    return MCRConfiguration2.getBoolean(CONFIG_ENABLED).orElse(true);
  }

  @Override
  public boolean validateWAFPassedCookie(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (!WAF_PASSED_COOKIE_NAME.equals(cookie.getName())) {
          continue;
        }
        return checkValidPassedToken(cookie.getValue(), request);
      }
    }
    return false;
  }

  /**
   * Checks if the provided token is valid by verifying its signature,
   * checking the IP claim against the client's IP address, and ensuring that the Proof of Work has been passed.
   * @param token the JWT token to validate
   * @param req the incoming HTTP request, used to retrieve the client's IP address for validation
   * @return true if the token is valid, false otherwise
   */
  private boolean checkValidPassedToken(String token, HttpServletRequest req) {
    DecodedJWT jwt;
    try {
      jwt = JWT.require(MCRJWTUtil.getJWTAlgorithm()).build().verify(token);
    } catch (JWTVerificationException e) {
      return false;
    }

    // check if the token contains the IP claim and if it matches the client's IP address
    Claim ipClaim = jwt.getClaim(IP_CLAIM);
    if (ipClaim.isNull()) {
      return false;
    }
    String tokenIP = ipClaim.asString();
    String remoteAddr = MCRFrontendUtil.getRemoteAddr(req);
    boolean ipEquals = remoteAddr.equals(tokenIP);
    if(!ipEquals) {
      return false;
    }

    // check if the token is a valid pow passed token
    Claim wafPassedClaim = jwt.getClaim(WAF_PASSED_CLAIM);
    // Other tokens signed with the same key (challenge, interaction) have no waf_passed claim
    return Boolean.TRUE.equals(wafPassedClaim.asBoolean());
  }

  @Override
  public void createWAFPassedCookie(HttpServletRequest request, HttpServletResponse response) {
    int passedTokenExpiryMinutes = MCRConfiguration2.getInt(CONFIG_PASSED_TOKEN_EXPIRY_MINUTES)
        .orElse(DEFAULT_PASSED_TOKEN_EXPIRY_MINUTES);
    String remoteAddr = MCRFrontendUtil.getRemoteAddr(request);
    String token = JWT.create()
        .withClaim(IP_CLAIM, remoteAddr)
        .withClaim(WAF_PASSED_CLAIM, true)
        .withExpiresAt(Date.from(Instant.now().plus(passedTokenExpiryMinutes, ChronoUnit.MINUTES)))
        .sign(MCRJWTUtil.getJWTAlgorithm());

    // Build Set-Cookie header manually: Servlet API < 6.0 has no native SameSite support
    boolean secure = MCRFrontendUtil.getBaseURL(request).startsWith("https://");
    String cookieHeader = WAF_PASSED_COOKIE_NAME + "=" + token
        + "; Path=/"
        + "; Max-Age=" + (passedTokenExpiryMinutes * 60)
        + "; HttpOnly"
        + "; SameSite=Lax"
        + (secure ? "; Secure" : "");
    response.addHeader("Set-Cookie", cookieHeader);
  }

  @Override
  public boolean hasSolution(HttpServletRequest request) {
    String powSolution = request.getParameter(POW_SOLUTION_PARAMETER);
    if(powSolution == null || powSolution.isEmpty()) {
      return false;
    }

    String information = request.getParameter(CLIENT_INFORMATION_PARAMETER);
    if(information == null || information.isEmpty()) {
      return false;
    }

    String challengeToken = request.getParameter(POW_CHALLENGE_TOKEN_PARAMETER);
    if(challengeToken == null || challengeToken.isEmpty()) {
      return false;
    }

    return true;
  }

  public DecodedJWT getChallengeTokenDecoded(HttpServletRequest req, String challengeToken) {
    // check if the challenge token is valid and corresponds to a previously generated challenge
    DecodedJWT jwt;
    try {
      jwt = JWT.require(MCRJWTUtil.getJWTAlgorithm()).build().verify(challengeToken);
    } catch (JWTVerificationException e) {
      return null;
    }

    return jwt;
  }

  @Override
  public boolean isValidSolution(HttpServletRequest request) {
    if(!hasSolution(request)) {
      return false;
    }
    String powSolution = request.getParameter(POW_SOLUTION_PARAMETER);
    String information = request.getParameter(CLIENT_INFORMATION_PARAMETER);

    String challengeToken = request.getParameter(POW_CHALLENGE_TOKEN_PARAMETER);
    DecodedJWT jwt = getChallengeTokenDecoded(request, challengeToken);
    if(jwt == null) {
      return false;
    }

    Claim ipClaim = jwt.getClaim(IP_CLAIM);
    if (ipClaim.isNull() || !MCRFrontendUtil.getRemoteAddr(request).equals(ipClaim.asString())) {
      return false;
    }

    Claim challengeClaim = jwt.getClaim(CHALLENGE_CLAIM);
    if(challengeClaim.isNull()) {
      return false;
    }
    String challenge = challengeClaim.asString();

    Claim difficultyClaim = jwt.getClaim(DIFFICULTY_CLAIM);
    if(difficultyClaim.isNull()) {
      return false;
    }
    int difficulty = difficultyClaim.asInt();

    if(!checkPowSolutionWithDifficulty(powSolution, challenge, difficulty)){
      return false;
    }

    if(!checkBotInformation(request, information)) {
      return false;
    }

    return true;
  }



  public boolean checkBotInformation(HttpServletRequest req, String information) {
    return botDetectionService.checkBotInformation(req, information);
  }

  @Override
  public void generateChallenge(HttpServletRequest request, HttpServletResponse resp) {
    // Check attempt count
    int attempt = getAttemptCount(request);
    int maxAttempts = MCRConfiguration2.getInt(CONFIG_MAX_ATTEMPTS).orElse(DEFAULT_MAX_ATTEMPTS);

    if (attempt >= maxAttempts) {
      showFailurePage(request, resp);
      return;
    }

    Locale locale = request.getLocale();
    String html = templateService.renderChallenge(locale,
        Map.of("pow_challenge_token", generateChallengeToken(request)));

    try {
      resp.setContentType("text/html;charset=UTF-8");
      resp.getWriter().write(html);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private int getAttemptCount(HttpServletRequest request) {
    String attemptParam = request.getParameter(ATTEMPT_PARAMETER);
    if (attemptParam == null || attemptParam.isEmpty()) {
      return 0;
    }
    try {
      return Integer.parseInt(attemptParam);
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private void showFailurePage(HttpServletRequest request, HttpServletResponse resp) {
    try {
      resp.setContentType("text/html;charset=UTF-8");
      resp.getWriter().write(templateService.renderFailPage(request.getLocale()));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private String generateChallengeToken(HttpServletRequest request) {
    // Generate a random challenge string
    String challenge = generateRandomChallenge();

    // Difficulty: number of leading zero bits required (16 = 4 hex zeros)
    int difficulty = MCRConfiguration2.getInt(CONFIG_DIFFICULTY).orElse(DEFAULT_DIFFICULTY);

    // Get redirect URL from request parameter (default to "/" if not present)
    String redirectURL = request.getParameter(REDIRECT_URL_PARAMETER);
    if (redirectURL == null || redirectURL.isEmpty()) {
      redirectURL = "/";
    }

    // Get attempt count from request parameter
    int attempt = getAttemptCount(request);

    // Create a JWT token containing the challenge, difficulty, redirect URL, and attempt
    int challengeExpiryMinutes = MCRConfiguration2.getInt(CONFIG_CHALLENGE_EXPIRY_MINUTES)
        .orElse(DEFAULT_CHALLENGE_EXPIRY_MINUTES);
    String token = JWT.create()
        .withClaim(CHALLENGE_CLAIM, challenge)
        .withClaim(DIFFICULTY_CLAIM, difficulty)
        .withClaim(REDIRECT_URL_CLAIM, redirectURL)
        .withClaim(ATTEMPT_CLAIM, attempt)
        .withClaim(IP_CLAIM, MCRFrontendUtil.getRemoteAddr(request))
        .withExpiresAt(Date.from(Instant.now().plus(challengeExpiryMinutes, ChronoUnit.MINUTES)))
        .sign(MCRJWTUtil.getJWTAlgorithm());

    return token;
  }

  private String generateRandomChallenge() {
    // Generate a random 32-character hexadecimal string
    byte[] randomBytes = new byte[16];
    secureRandom.nextBytes(randomBytes);
    StringBuilder sb = new StringBuilder();
    for (byte b : randomBytes) {
      sb.append(String.format(Locale.ROOT, "%02x", b));
    }
    return sb.toString();
  }

  private boolean checkPowSolutionWithDifficulty(String powSolution, String challenge, int difficulty) {
    return powValidator.validate(powSolution, challenge, difficulty);
  }

  @Override
  public void redirectToChallenge(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    redirectToChallengeWithAttempt(request, response, 0);
  }

  public void redirectToChallengeWithAttempt(HttpServletRequest request, HttpServletResponse response, int attempt)
      throws IOException {
    // Get the original URL relative to base URL
    String requestURI = request.getRequestURI();
    String baseURL = MCRFrontendUtil.getBaseURL(request);
    String basePath = URI.create(baseURL).getPath();
    if (basePath.endsWith("/")) {
      basePath = basePath.substring(0, basePath.length() - 1);
    }

    // Make URL relative to base
    String relativeURL = requestURI;
    if (!basePath.isEmpty() && requestURI.startsWith(basePath)) {
      relativeURL = requestURI.substring(basePath.length());
    }

    // Add query string if present (but only if it's not a challenge request)
    if (!isChallengeRequest(request) && !isChallengeSolutionRequest(request)) {
      String queryString = request.getQueryString();
      if (queryString != null && !queryString.isEmpty()) {
        relativeURL += "?" + queryString;
      }
    }

    // Build redirect URL with parameters
    StringBuilder redirectURL = new StringBuilder(joinPaths(baseURL, "pow-challenge"));
    redirectURL.append("?").append(REDIRECT_URL_PARAMETER).append("=")
        .append(java.net.URLEncoder.encode(relativeURL, StandardCharsets.UTF_8));

    if (attempt > 0) {
      redirectURL.append("&").append(ATTEMPT_PARAMETER).append("=").append(attempt);
    }

    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.sendRedirect(redirectURL.toString());
  }

  private String joinPaths(String base, String path) {
    // Remove trailing slash from base if present
    if (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    // Ensure path starts with slash
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    return base + path;
  }

  private String getChallengePath(HttpServletRequest request) {
    String basePath = URI.create(MCRFrontendUtil.getBaseURL(request)).getPath();
    if (basePath.endsWith("/")) {
      basePath = basePath.substring(0, basePath.length() - 1);
    }
    return basePath + "/pow-challenge";
  }

  @Override
  public boolean isChallengeRequest(HttpServletRequest request) {
    return request.getRequestURI().equals(getChallengePath(request))
        && request.getMethod().equalsIgnoreCase("GET");
  }

  @Override
  public boolean isChallengeSolutionRequest(HttpServletRequest request) {
    return request.getRequestURI().equals(getChallengePath(request))
        && request.getMethod().equalsIgnoreCase("POST");
  }

  @Override
  public void redirectAfterChallenge(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    // Extract redirect URL from the challenge or interaction token
    String challengeToken = getFlowToken(request);
    if (challengeToken == null || challengeToken.isEmpty()) {
      // Fallback to root if no token
      response.sendRedirect(joinPaths(MCRFrontendUtil.getBaseURL(request), "/"));
      return;
    }

    DecodedJWT jwt = getChallengeTokenDecoded(request, challengeToken);
    if (jwt == null) {
      // Fallback to root if token is invalid
      response.sendRedirect(joinPaths(MCRFrontendUtil.getBaseURL(request), "/"));
      return;
    }

    Claim redirectClaim = jwt.getClaim(REDIRECT_URL_CLAIM);
    String redirectURL = redirectClaim.isNull() ? "/" : redirectClaim.asString();

    // Redirect to the original URL
    response.sendRedirect(joinPaths(MCRFrontendUtil.getBaseURL(request), redirectURL));
  }

  @Override
  public void redirectAfterFailedAttempt(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    // Extract attempt and redirect URL from the challenge or interaction token
    String challengeToken = getFlowToken(request);
    if (challengeToken == null || challengeToken.isEmpty()) {
      // Fallback to challenge page with attempt 1
      redirectToChallengeWithAttempt(request, response, 1);
      return;
    }

    DecodedJWT jwt = getChallengeTokenDecoded(request, challengeToken);
    if (jwt == null) {
      // Fallback to challenge page with attempt 1
      redirectToChallengeWithAttempt(request, response, 1);
      return;
    }

    Claim attemptClaim = jwt.getClaim(ATTEMPT_CLAIM);
    int currentAttempt = attemptClaim.isNull() ? 0 : attemptClaim.asInt();

    Claim redirectClaim = jwt.getClaim(REDIRECT_URL_CLAIM);
    String redirectURL = redirectClaim.isNull() ? "/" : redirectClaim.asString();

    // Increment attempt and redirect to challenge page
    int newAttempt = currentAttempt + 1;

    String baseURL = MCRFrontendUtil.getBaseURL(request);
    StringBuilder challengeURL = new StringBuilder(joinPaths(baseURL, "pow-challenge"));
    challengeURL.append("?").append(REDIRECT_URL_PARAMETER).append("=")
        .append(java.net.URLEncoder.encode(redirectURL, StandardCharsets.UTF_8));
    challengeURL.append("&").append(ATTEMPT_PARAMETER).append("=").append(newAttempt);

    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.sendRedirect(challengeURL.toString());
  }

  @Override
  public boolean isIPAllowed(HttpServletRequest request) {
    return allowListChecker.isIPAllowed(request);
  }

  @Override
  public boolean isPathAllowed(HttpServletRequest request) {
    return allowListChecker.isPathAllowed(request);
  }

  @Override
  public boolean isAllowedSubResource(HttpServletRequest request) {
    return allowListChecker.isAllowedSubResource(request);
  }

  @Override
  public boolean isKnownBotAllowedByReverseDNS(HttpServletRequest request) {
    return allowListChecker.isKnownBotAllowedByReverseDNS(request);
  }

  @Override
  public boolean isRuleAllowed(HttpServletRequest request) {
    return allowRules.isAllowed(request);
  }

  /**
   * Returns the token that carries the redirect URL and the attempt counter of the current
   * challenge flow: the interaction token if an interaction challenge is submitted, the Proof of
   * Work challenge token otherwise.
   */
  private static String getFlowToken(HttpServletRequest request) {
    String interactionToken = request.getParameter(INTERACTION_TOKEN_PARAMETER);
    if (interactionToken != null && !interactionToken.isEmpty()) {
      return interactionToken;
    }
    return request.getParameter(POW_CHALLENGE_TOKEN_PARAMETER);
  }

  @Override
  public List<String> findSuspicionReasons(HttpServletRequest request) {
    DecodedJWT jwt = getChallengeTokenDecoded(request, request.getParameter(POW_CHALLENGE_TOKEN_PARAMETER));
    String redirectURL = jwt == null || jwt.getClaim(REDIRECT_URL_CLAIM).isNull()
        ? null
        : jwt.getClaim(REDIRECT_URL_CLAIM).asString();
    return suspicionRules.findMatchingRules(request, request.getParameter(CLIENT_INFORMATION_PARAMETER),
        MCRFrontendUtil.getRemoteAddr(request), redirectURL, geoIP);
  }

  @Override
  public void generateInteractionChallenge(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    DecodedJWT challengeJWT = getChallengeTokenDecoded(request,
        request.getParameter(POW_CHALLENGE_TOKEN_PARAMETER));
    String redirectURL = "/";
    int attempt = 0;
    if (challengeJWT != null) {
      Claim redirectClaim = challengeJWT.getClaim(REDIRECT_URL_CLAIM);
      redirectURL = redirectClaim.isNull() ? "/" : redirectClaim.asString();
      Claim attemptClaim = challengeJWT.getClaim(ATTEMPT_CLAIM);
      attempt = attemptClaim.isNull() ? 0 : attemptClaim.asInt();
    }

    // Random checkbox position in per mille of the canvas size. The vertical position avoids the
    // middle of the page, where the explanation is drawn.
    int boxX = 50 + secureRandom.nextInt(801);
    int boxY = secureRandom.nextBoolean() ? 60 + secureRandom.nextInt(161) : 720 + secureRandom.nextInt(181);

    int expiryMinutes = MCRConfiguration2.getInt(CONFIG_INTERACTION_EXPIRY_MINUTES)
        .orElse(DEFAULT_INTERACTION_EXPIRY_MINUTES);
    String token = JWT.create()
        .withClaim(STAGE_CLAIM, STAGE_INTERACTION)
        .withClaim(BOX_X_CLAIM, boxX)
        .withClaim(BOX_Y_CLAIM, boxY)
        .withClaim(REDIRECT_URL_CLAIM, redirectURL)
        .withClaim(ATTEMPT_CLAIM, attempt)
        .withClaim(IP_CLAIM, MCRFrontendUtil.getRemoteAddr(request))
        .withExpiresAt(Date.from(Instant.now().plus(expiryMinutes, ChronoUnit.MINUTES)))
        .sign(MCRJWTUtil.getJWTAlgorithm());

    JsonObject config = new JsonObject();
    config.addProperty("token", token);
    config.addProperty("boxX", boxX);
    config.addProperty("boxY", boxY);
    config.addProperty("boxSize", InteractionValidator.BOX_SIZE);
    config.addProperty("margin", InteractionValidator.MARGIN);

    response.setContentType("text/html;charset=UTF-8");
    response.setHeader("Cache-Control", "no-store");
    response.getWriter().write(templateService.renderInteraction(request.getLocale(), config));
  }

  @Override
  public boolean hasInteraction(HttpServletRequest request) {
    String token = request.getParameter(INTERACTION_TOKEN_PARAMETER);
    String events = request.getParameter(INTERACTION_EVENTS_PARAMETER);
    return token != null && !token.isEmpty() && events != null && !events.isEmpty();
  }

  @Override
  public List<String> checkInteraction(HttpServletRequest request) {
    DecodedJWT jwt = getChallengeTokenDecoded(request, request.getParameter(INTERACTION_TOKEN_PARAMETER));
    if (jwt == null) {
      return List.of("invalid or expired interaction token");
    }
    if (!STAGE_INTERACTION.equals(jwt.getClaim(STAGE_CLAIM).asString())) {
      return List.of("token is not an interaction token");
    }
    Claim ipClaim = jwt.getClaim(IP_CLAIM);
    if (ipClaim.isNull() || !MCRFrontendUtil.getRemoteAddr(request).equals(ipClaim.asString())) {
      return List.of("interaction token was issued for another IP");
    }
    Integer boxX = jwt.getClaim(BOX_X_CLAIM).asInt();
    Integer boxY = jwt.getClaim(BOX_Y_CLAIM).asInt();
    if (boxX == null || boxY == null) {
      return List.of("interaction token without checkbox position");
    }
    return interactionValidator.validate(request.getParameter(INTERACTION_EVENTS_PARAMETER), boxX, boxY);
  }

}
