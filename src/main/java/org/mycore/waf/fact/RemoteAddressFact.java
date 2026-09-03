package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.math.BigInteger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
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

    private static final Pattern NEVER_MATCHES = Pattern.compile("(?!)");

    @XmlAttribute
    private String cidr;

    @XmlAttribute
    private String pattern;

    private transient IPRange range;

    private transient Pattern compiledPattern;

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
        if (range == null) {
            try {
                range = IPRange.parse(cidr);
            } catch (IllegalArgumentException e) {
                LOGGER.error("Invalid CIDR range '{}' in remote-address fact: {}", cidr, e.getMessage());
                range = new IPRange(BigInteger.ONE, BigInteger.ZERO);
            }
        }
        return range;
    }

    private Pattern getCompiledPattern() {
        if (compiledPattern == null) {
            try {
                compiledPattern = Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                LOGGER.error("Invalid regular expression '{}' in remote-address fact: {}", pattern, e.getMessage());
                compiledPattern = NEVER_MATCHES;
            }
        }
        return compiledPattern;
    }

}
