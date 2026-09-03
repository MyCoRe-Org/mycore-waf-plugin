package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.frontend.MCRFrontendUtil;
import org.mycore.waf.IPRange;

/**
 * A fact that checks the client IP address of the request, honoring trusted proxies. With the
 * {@code cidr} attribute the address must lie in the given IP range, for example
 * {@code 66.249.64.0/19} or a single address like {@code 192.168.1.5}. With the {@code pattern}
 * attribute a Java regex is matched against the address string. If both are configured, the
 * {@code cidr} attribute takes precedence. The fact never matches if neither is configured.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class RemoteAddressFact extends Fact {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlAttribute
    private String cidr;

    @XmlAttribute
    private String pattern;

    private transient volatile IPRange range;

    private transient volatile boolean invalidRange;

    private transient volatile Pattern compiledPattern;

    @Override
    public boolean matches(HttpServletRequest request) {
        if (cidr == null && pattern == null) {
            LOGGER.warn("remote-address fact without cidr or pattern never matches");
            return false;
        }
        String remoteAddress = MCRFrontendUtil.getRemoteAddr(request);
        if (remoteAddress == null) {
            return false;
        }
        if (cidr != null) {
            IPRange ipRange = getRange();
            return ipRange != null && ipRange.contains(remoteAddress);
        }
        Pattern p = getCompiledPattern();
        return p != null && p.matcher(remoteAddress).matches();
    }

    private IPRange getRange() {
        if (range == null && !invalidRange) {
            try {
                range = IPRange.parse(cidr);
            } catch (IllegalArgumentException e) {
                LOGGER.error("Invalid CIDR range '{}' in remote-address fact: {}", cidr, e.getMessage());
                invalidRange = true;
            }
        }
        return range;
    }

    private Pattern getCompiledPattern() {
        if (compiledPattern == null) {
            compiledPattern = RegexFact.compilePattern(pattern, "remote-address fact");
        }
        return compiledPattern;
    }

    @Override
    void validate() {
        if (cidr != null) {
            try {
                range = IPRange.parse(cidr);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid CIDR range '" + cidr + "' in remote-address fact", e);
            }
        } else if (pattern != null) {
            compiledPattern = RegexFact.requireValidPattern(pattern, "remote-address fact");
        } else {
            throw new IllegalArgumentException("remote-address fact has neither cidr nor pattern");
        }
    }

}
