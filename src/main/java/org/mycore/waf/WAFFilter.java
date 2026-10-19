package org.mycore.waf;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.frontend.MCRFrontendUtil;


public class WAFFilter extends HttpFilter {

  private static final Logger LOGGER = LogManager.getLogger();

  // Limits client controlled values in the log, the client information of a browser is far shorter
  private static final int MAX_LOGGED_VALUE_LENGTH = 2000;

  // The recorded interaction events are logged completely, the challenge page limits their number
  private static final int MAX_LOGGED_EVENTS_LENGTH = 200_000;

  @Override
  public void init() throws ServletException {
    super.init();
    wafService = new DefaultWAFService();
  }

  WAFService wafService;

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    if (!handle(req, res)) {
      return;
    }

    chain.doFilter(req, res);
  }

  /**
   * Handles the WAF mechanism for incoming requests.
   *
   * @param req the incoming HTTP request
   * @param res the outgoing HTTP response
   * @return true if the request should proceed through the filter chain, false if a response has
   * been sent to the client and the filter chain should not continue.
   */
  private boolean handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
    String ipInfo = null;
    if (LOGGER.isDebugEnabled()) {
      ipInfo = MCRFrontendUtil.getRemoteAddr(req);
    }

    if (wafService == null || !wafService.isEnabled()) {
      LOGGER.debug("{} WAF is not enabled. Allowing request to proceed.", ipInfo);
      return true;
    }

    // Check if path is on allow list
    if (wafService.isPathAllowed(req)) {
      LOGGER.debug("{} Path is on allow list. Allowing request to proceed.", ipInfo);
      return true;
    }

    // Check if IP is on allow list
    if (wafService.isIPAllowed(req)) {
      LOGGER.debug("{} IP is on allow list. Allowing request to proceed.", ipInfo);
      return true;
    }

    // Check if the request matches the configured XML allow rules
    if (wafService.isRuleAllowed(req)) {
      LOGGER.debug("{} Request matches XML allow rules. Allowing request to proceed.", ipInfo);
      return true;
    }

    // Check if this is a browser sub resource request (CSS, JS, images, ...) that cannot
    // solve a challenge on its own
    if (wafService.isAllowedSubResource(req)) {
      LOGGER.debug("{} Request is an allowed sub resource. Allowing request to proceed.", ipInfo);
      return true;
    }

    if (wafService.validateWAFPassedCookie(req)) {
      LOGGER.debug("{} Valid WAF-PASSED cookie found. Allowing request to proceed.", ipInfo);
      return true;
    }

    // Check if request is from a known bot verified via reverse DNS
    if (wafService.isKnownBotAllowedByReverseDNS(req)) {
      LOGGER.debug("{} Known bot verified via reverse DNS. Allowing request to proceed.", ipInfo);
      return true;
    }

    if (wafService.isChallengeSolutionRequest(req) && wafService.hasInteraction(req)) {
      return handleInteraction(req, res);
    }

    if (wafService.isChallengeSolutionRequest(req) && wafService.hasSolution(req)) {
      LOGGER.debug(
          "{} Valid WAF challenge solution received. Validating solution.",
          ipInfo);
      if (wafService.isValidSolution(req)) {
        List<String> suspicionReasons = wafService.findSuspicionReasons(req);
        if (!suspicionReasons.isEmpty()) {
          logChallengeResult(req, Level.INFO, "solved, but the client is suspicious " + suspicionReasons
              + ", showing interaction challenge");
          wafService.generateInteractionChallenge(req, res);
          return false;
        }
        LOGGER.debug("{} WAF challenge solution is valid. Creating WAF-PASSED cookie and redirecting to original URL.", ipInfo);
        logChallengeResult(req, Level.DEBUG, "solved");
        wafService.createWAFPassedCookie(req, res);
        wafService.redirectAfterChallenge(req, res);
        return false;
      } else {
        LOGGER.debug("{} WAF challenge solution is invalid. Incrementing attempt and redirecting to challenge page.",
            ipInfo);
        logChallengeResult(req, Level.INFO, "solution rejected");
        wafService.redirectAfterFailedAttempt(req, res);
        return false;
      }
    }

    if (wafService.isChallengeRequest(req)) {
      LOGGER.debug("{} Challenge request received. Generating challenge.", ipInfo);
      wafService.generateChallenge(req, res);
      return false;
    }

    LOGGER.debug(
        "{} No valid WAF-PASSED cookie or challenge solution found. Redirecting to challenge page.",
        ipInfo);
    wafService.redirectToChallenge(req, res);
    return false;
  }

  /**
   * Validates the result of the interaction challenge that is shown to suspicious clients. The
   * recorded events are written to the debug log, so that the behavior of bots that pass the
   * interaction challenge can be analyzed later.
   */
  private boolean handleInteraction(HttpServletRequest req, HttpServletResponse res) throws IOException {
    String remoteAddress = MCRFrontendUtil.getRemoteAddr(req);
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("{} WAF interaction events: {}", remoteAddress,
          sanitizeForLog(req.getParameter(DefaultWAFService.INTERACTION_EVENTS_PARAMETER), MAX_LOGGED_EVENTS_LENGTH));
    }
    List<String> problems = wafService.checkInteraction(req);
    String userAgent = sanitizeForLog(req.getHeader("User-Agent"));
    if (problems.isEmpty()) {
      LOGGER.info("{} WAF interaction challenge solved. User-Agent: {}", remoteAddress, userAgent);
      wafService.createWAFPassedCookie(req, res);
      wafService.redirectAfterChallenge(req, res);
    } else {
      LOGGER.info("{} WAF interaction challenge rejected {}. User-Agent: {}", remoteAddress,
          sanitizeForLog(problems.toString()), userAgent);
      wafService.redirectAfterFailedAttempt(req, res);
    }
    return false;
  }

  /**
   * Logs the outcome of a challenge solution together with the User-Agent and the client
   * information sent by the challenge page, so that browsers and scripts solving the challenge can
   * be told apart. Solved challenges are frequent and logged at debug level only, rejected
   * solutions are logged at info level.
   *
   * @param req the challenge solution request
   * @param level the log level to use
   * @param result the outcome to log
   */
  private static void logChallengeResult(HttpServletRequest req, Level level, String result) {
    if (!LOGGER.isEnabled(level)) {
      return;
    }
    LOGGER.log(level, "{} WAF challenge {}. User-Agent: {} Client information: {}",
        MCRFrontendUtil.getRemoteAddr(req), result,
        sanitizeForLog(req.getHeader("User-Agent")),
        sanitizeForLog(req.getParameter(DefaultWAFService.CLIENT_INFORMATION_PARAMETER)));
  }

  /**
   * Prepares a client controlled value for the log: control characters are replaced so that a
   * client cannot forge additional log lines, and overly long values are truncated.
   *
   * @param value the value to sanitize, may be null
   * @return the sanitized value, or "-" if the value is null
   */
  static String sanitizeForLog(String value) {
    return sanitizeForLog(value, MAX_LOGGED_VALUE_LENGTH);
  }

  /**
   * Prepares a client controlled value for the log, see {@link #sanitizeForLog(String)}.
   *
   * @param value the value to sanitize, may be null
   * @param maxLength the maximal length of the logged value
   * @return the sanitized value, or "-" if the value is null
   */
  static String sanitizeForLog(String value, int maxLength) {
    if (value == null) {
      return "-";
    }
    String sanitized = value.replaceAll("\\p{Cntrl}", "?");
    if (sanitized.length() > maxLength) {
      return sanitized.substring(0, maxLength) + "...";
    }
    return sanitized;
  }
}
