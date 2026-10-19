package org.mycore.waf.fact;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.frontend.MCRFrontendUtil;
import org.mycore.waf.RemoteAddressMatcher;

/**
 * A fact that checks the client IP address of the request, honoring trusted proxies. With the
 * {@code cidr} attribute the address must lie in one of the given comma separated IP ranges, for
 * example {@code 66.249.64.0/19} or a single address like {@code 192.168.1.5}. With the
 * {@code pattern} attribute a Java regex is matched against the address string. If both are
 * configured, the {@code cidr} attribute takes precedence. The fact never matches if neither is
 * configured. See {@link RemoteAddressMatcher}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class RemoteAddressFact extends Fact {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String CONTEXT = "remote-address fact";

    @XmlAttribute
    private String cidr;

    @XmlAttribute
    private String pattern;

    private transient volatile RemoteAddressMatcher matcher;

    private transient volatile boolean invalid;

    @Override
    public boolean matches(HttpServletRequest request) {
        RemoteAddressMatcher m = getMatcher();
        return m != null && m.matches(MCRFrontendUtil.getRemoteAddr(request));
    }

    private RemoteAddressMatcher getMatcher() {
        if (matcher == null && !invalid) {
            try {
                matcher = RemoteAddressMatcher.of(cidr, pattern, CONTEXT);
            } catch (IllegalArgumentException e) {
                LOGGER.error("{}, the fact never matches", e.getMessage());
                invalid = true;
            }
        }
        return matcher;
    }

    @Override
    void validate() {
        matcher = RemoteAddressMatcher.of(cidr, pattern, CONTEXT);
    }

}
