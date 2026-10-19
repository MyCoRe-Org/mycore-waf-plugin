package org.mycore.waf;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IPRangeTest {

    // --- IPv4 single address ---

    @Test
    void ipv4SingleAddress_matchesSelf() {
        IPRange range = IPRange.parse("192.168.1.5");
        assertTrue(range.contains("192.168.1.5"));
    }

    @Test
    void ipv4SingleAddress_doesNotMatchOther() {
        IPRange range = IPRange.parse("192.168.1.5");
        assertFalse(range.contains("192.168.1.6"));
    }

    // --- IPv4 CIDR ---

    @Test
    void ipv4Cidr_matchesNetworkAddress() {
        IPRange range = IPRange.parse("192.168.1.0/24");
        assertTrue(range.contains("192.168.1.0"));
    }

    @Test
    void ipv4Cidr_matchesBroadcastAddress() {
        IPRange range = IPRange.parse("192.168.1.0/24");
        assertTrue(range.contains("192.168.1.255"));
    }

    @Test
    void ipv4Cidr_matchesAddressInRange() {
        IPRange range = IPRange.parse("192.168.1.0/24");
        assertTrue(range.contains("192.168.1.100"));
    }

    @Test
    void ipv4Cidr_doesNotMatchAddressOutsideRange() {
        IPRange range = IPRange.parse("192.168.1.0/24");
        assertFalse(range.contains("192.168.2.1"));
    }

    @Test
    void ipv4Cidr_slash32_matchesSingleHost() {
        IPRange range = IPRange.parse("10.0.0.1/32");
        assertTrue(range.contains("10.0.0.1"));
        assertFalse(range.contains("10.0.0.2"));
    }

    @Test
    void ipv4Cidr_slash0_matchesEverything() {
        IPRange range = IPRange.parse("0.0.0.0/0");
        assertTrue(range.contains("1.2.3.4"));
        assertTrue(range.contains("255.255.255.255"));
        assertFalse(range.contains("::1"));
    }

    @Test
    void ipv4Cidr_slash16() {
        IPRange range = IPRange.parse("10.20.0.0/16");
        assertTrue(range.contains("10.20.0.1"));
        assertTrue(range.contains("10.20.255.255"));
        assertFalse(range.contains("10.21.0.0"));
        assertFalse(range.contains("10.19.255.255"));
    }

    @Test
    void ipv4Cidr_hostNotOnNetworkBoundary_stillComputesCorrectNetwork() {
        // 192.168.1.100/24 should behave the same as 192.168.1.0/24
        IPRange range = IPRange.parse("192.168.1.100/24");
        assertTrue(range.contains("192.168.1.1"));
        assertTrue(range.contains("192.168.1.254"));
        assertFalse(range.contains("192.168.2.1"));
    }

    // --- IPv6 single address ---

    @Test
    void ipv6SingleAddress_matchesSelf() {
        IPRange range = IPRange.parse("2001:db8::1");
        assertTrue(range.contains("2001:db8::1"));
    }

    @Test
    void ipv6SingleAddress_doesNotMatchOther() {
        IPRange range = IPRange.parse("2001:db8::1");
        assertFalse(range.contains("2001:db8::2"));
    }

    // --- IPv6 CIDR ---

    @Test
    void ipv6Cidr_matchesAddressInRange() {
        IPRange range = IPRange.parse("2001:db8::/32");
        assertTrue(range.contains("2001:db8::1"));
        assertTrue(range.contains("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    @Test
    void ipv6Cidr_doesNotMatchAddressOutsideRange() {
        IPRange range = IPRange.parse("2001:db8::/32");
        assertFalse(range.contains("2001:db9::1"));
    }

    @Test
    void ipv6Cidr_slash128_matchesSingleHost() {
        IPRange range = IPRange.parse("2001:db8::1/128");
        assertTrue(range.contains("2001:db8::1"));
        assertFalse(range.contains("2001:db8::2"));
    }

    @Test
    void ipv6Cidr_slash64() {
        IPRange range = IPRange.parse("fe80::/64");
        assertTrue(range.contains("fe80::1"));
        assertTrue(range.contains("fe80::ffff:ffff:ffff:ffff"));
        assertFalse(range.contains("fe80:0:0:1::1"));
    }

    @Test
    void ipv6Cidr_slash0DoesNotMatchIpv4Address() {
        IPRange range = IPRange.parse("::/0");
        assertTrue(range.contains("2001:db8::1"));
        assertFalse(range.contains("8.8.8.8"));
    }

    // --- Cross-family: IPv4 range vs IPv6 address ---

    @Test
    void ipv4Range_doesNotMatchIpv6Address() {
        IPRange range = IPRange.parse("192.168.1.0/24");
        assertFalse(range.contains("::1"));
    }

    @Test
    void ipv6Range_doesNotMatchIpv4Address() {
        IPRange range = IPRange.parse("2001:db8::/32");
        assertFalse(range.contains("192.168.1.1"));
    }

    @Test
    void publicConstructor_doesNotMixAddressFamilies() {
        IPRange ipv4Range = new IPRange(BigInteger.ZERO, BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE));
        assertTrue(ipv4Range.contains("127.0.0.1"));
        assertFalse(ipv4Range.contains("::1"));

        IPRange ipv6Range = new IPRange(BigInteger.ZERO, BigInteger.ONE.shiftLeft(64));
        assertTrue(ipv6Range.contains("::1"));
        assertFalse(ipv6Range.contains("127.0.0.1"));
    }

    // --- Invalid input ---

    @Test
    void parse_invalidAddress_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> IPRange.parse("not-an-ip"));
    }

    @Test
    void parse_negativePrefix_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> IPRange.parse("192.168.1.0/-1"));
    }

    @Test
    void parse_prefixBeyondAddressLength_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> IPRange.parse("192.168.1.0/33"));
        assertThrows(IllegalArgumentException.class, () -> IPRange.parse("2001:db8::/129"));
    }

    @Test
    void contains_invalidAddress_returnsFalse() {
        IPRange range = IPRange.parse("192.168.1.0/24");
        assertFalse(range.contains("not-an-ip"));
    }
}
