package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import org.mycore.waf.RemoteAddressMatcher;

/**
 * A fact that checks the client IP address, honoring trusted proxies. It has the same semantics as
 * the {@code remote-address} fact of the allow rules: with the {@code cidr} attribute the address
 * must lie in one of the given comma separated IP ranges, for example
 * {@code 47.74.0.0/15, 8.208.0.0/12}. With the {@code pattern} attribute a Java regex is matched
 * against the address string. If both are configured, {@code cidr} takes precedence. See
 * {@link RemoteAddressMatcher}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class RemoteAddressFact extends ClientFact {

    private static final String CONTEXT = "remote-address fact";

    @XmlAttribute
    private String cidr;

    @XmlAttribute
    private String pattern;

    private transient volatile RemoteAddressMatcher matcher;

    @Override
    public boolean matches(ClientInformation information) {
        if (matcher == null) {
            validate();
        }
        return matcher.matches(information.remoteAddress());
    }

    @Override
    void validate() {
        matcher = RemoteAddressMatcher.of(cidr, pattern, CONTEXT);
    }

}
