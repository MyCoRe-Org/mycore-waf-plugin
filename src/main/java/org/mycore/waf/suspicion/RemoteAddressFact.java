package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.mycore.waf.IPRange;

/**
 * A fact that checks the client IP address, honoring trusted proxies. With the {@code cidr}
 * attribute the address must lie in one of the given comma separated IP ranges, for example
 * {@code 47.74.0.0/15, 8.208.0.0/12}. With the {@code pattern} attribute a Java regex is matched
 * against the address string. If both are configured, the address has to satisfy both.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class RemoteAddressFact extends ClientFact {

    @XmlAttribute
    private String cidr;

    @XmlAttribute
    private String pattern;

    private transient volatile List<IPRange> ranges;

    private transient volatile Pattern compiledPattern;

    @Override
    public boolean matches(ClientInformation information) {
        String remoteAddress = information.remoteAddress();
        if (remoteAddress == null) {
            return false;
        }
        if (ranges == null) {
            validate();
        }
        if (!ranges.isEmpty() && ranges.stream().noneMatch(range -> range.contains(remoteAddress))) {
            return false;
        }
        return compiledPattern == null || compiledPattern.matcher(remoteAddress).matches();
    }

    @Override
    void validate() {
        if (cidr == null && pattern == null) {
            throw new IllegalArgumentException("remote-address fact has neither cidr nor pattern");
        }
        List<IPRange> parsedRanges = new ArrayList<>();
        if (cidr != null) {
            for (String part : cidr.split(",")) {
                String trimmed = part.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                try {
                    parsedRanges.add(IPRange.parse(trimmed));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException(
                        "Invalid CIDR range '" + trimmed + "' in remote-address fact", e);
                }
            }
        }
        if (pattern != null) {
            try {
                compiledPattern = Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(
                    "Invalid regular expression '" + pattern + "' in remote-address fact", e);
            }
        }
        ranges = parsedRanges;
    }

}
