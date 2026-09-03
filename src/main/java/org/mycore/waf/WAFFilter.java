package org.mycore.waf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.frontend.MCRFrontendUtil;

public class WAFFilter extends HttpFilter {

    private static final Logger LOGGER = LogManager.getLogger();

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

        if (wafService.isChallengeSolutionRequest(req) && wafService.hasSolution(req)) {
            LOGGER.debug(
                "{} Valid WAF challenge solution received. Validating solution.",
                ipInfo);
            if (wafService.isValidSolution(req)) {
                LOGGER.debug(
                    "{} WAF challenge solution is valid. Creating WAF-PASSED cookie and redirecting to original URL.",
                    ipInfo);
                wafService.createWAFPassedCookie(req, res);
                wafService.redirectAfterChallenge(req, res);
                return false;
            } else {
                LOGGER.debug(
                    "{} WAF challenge solution is invalid. Incrementing attempt and redirecting to challenge page.",
                    ipInfo);
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

}
