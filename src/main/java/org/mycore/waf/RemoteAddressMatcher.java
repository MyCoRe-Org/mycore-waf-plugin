package org.mycore.waf;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Matches a client IP address against the {@code cidr} and {@code pattern} attributes of the
 * {@code remote-address} facts of the allow and the suspicion rules. {@code cidr} is a comma
 * separated list of IP ranges or single addresses, for example {@code 66.249.64.0/19, 192.168.1.5}.
 * {@code pattern} is a Java regex matched against the address string. If both are given,
 * {@code cidr} takes precedence and {@code pattern} is ignored.
 */
public final class RemoteAddressMatcher {

    private final List<IPRange> ranges;

    private final Pattern pattern;

    private RemoteAddressMatcher(List<IPRange> ranges, Pattern pattern) {
        this.ranges = ranges;
        this.pattern = pattern;
    }

    /**
     * Creates a matcher.
     *
     * @param cidr comma separated IP ranges, or null
     * @param pattern a regular expression, or null
     * @param context a description of the fact for error messages
     * @return the matcher
     * @throws IllegalArgumentException if neither is given or a value is invalid
     */
    public static RemoteAddressMatcher of(String cidr, String pattern, String context) {
        if (cidr != null) {
            List<IPRange> ranges = new ArrayList<>();
            for (String part : cidr.split(",")) {
                String trimmed = part.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                try {
                    ranges.add(IPRange.parse(trimmed));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid CIDR range '" + trimmed + "' in " + context, e);
                }
            }
            if (ranges.isEmpty()) {
                throw new IllegalArgumentException("Empty cidr attribute in " + context);
            }
            return new RemoteAddressMatcher(ranges, null);
        }
        if (pattern != null) {
            return new RemoteAddressMatcher(List.of(), WAFRegex.requireValidPattern(pattern, context));
        }
        throw new IllegalArgumentException(context + " has neither cidr nor pattern");
    }

    /**
     * Checks an IP address.
     *
     * @param address the IP address, may be null
     * @return true if the address lies in one of the ranges or matches the pattern
     */
    public boolean matches(String address) {
        if (address == null) {
            return false;
        }
        if (pattern != null) {
            return pattern.matcher(address).matches();
        }
        return ranges.stream().anyMatch(range -> range.contains(address));
    }

}
