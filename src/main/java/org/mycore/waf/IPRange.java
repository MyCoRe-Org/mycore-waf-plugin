package org.mycore.waf;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Represents an IP address range supporting CIDR notation for both IPv4 and IPv6.
 */
public class IPRange {
    private static final int IPV4_ADDRESS_LENGTH = 4;
    private static final int IPV6_ADDRESS_LENGTH = 16;

    private final BigInteger networkAddress;
    private final BigInteger broadcastAddress;
    private final int addressLength;

    /**
     * Creates an IP range from numeric boundaries. IPv4 is assumed when both values fit into 32 bits, otherwise IPv6 is
     * assumed.
     *
     * @param networkAddress the first address in the range
     * @param broadcastAddress the last address in the range
     */
    public IPRange(BigInteger networkAddress, BigInteger broadcastAddress) {
        this(networkAddress, broadcastAddress,
            networkAddress.bitLength() <= 32 && broadcastAddress.bitLength() <= 32
                ? IPV4_ADDRESS_LENGTH
                : IPV6_ADDRESS_LENGTH);
    }

    private IPRange(BigInteger networkAddress, BigInteger broadcastAddress, int addressLength) {
        this.networkAddress = networkAddress;
        this.broadcastAddress = broadcastAddress;
        this.addressLength = addressLength;
    }

    /**
     * Parses an IP range from a string.
     * Supports single addresses and CIDR notation for both IPv4 and IPv6.
     * Examples: "192.168.1.1", "192.168.1.0/24", "2001:db8::/32"
     *
     * @param cidr the IP range string
     * @return the parsed IPRange
     * @throws IllegalArgumentException if the format is invalid
     */
    public static IPRange parse(String cidr) {
        try {
            if (cidr.contains("/")) {
                String[] parts = cidr.split("/", 2);
                InetAddress addr = InetAddress.getByName(parts[0]);
                int prefixLength = Integer.parseInt(parts[1]);
                int bits = addr.getAddress().length * 8; // 32 for IPv4, 128 for IPv6
                if (prefixLength < 0 || prefixLength > bits) {
                    throw new IllegalArgumentException("Invalid prefix length for " + parts[0] + ": " + prefixLength);
                }

                BigInteger ip = new BigInteger(1, addr.getAddress());
                BigInteger allOnes = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
                BigInteger hostMask = BigInteger.ONE.shiftLeft(bits - prefixLength).subtract(BigInteger.ONE);
                BigInteger networkMask = allOnes.xor(hostMask);
                BigInteger network = ip.and(networkMask);
                BigInteger broadcast = network.or(hostMask);

                return new IPRange(network, broadcast, addr.getAddress().length);
            } else {
                InetAddress addr = InetAddress.getByName(cidr);
                BigInteger ip = new BigInteger(1, addr.getAddress());
                return new IPRange(ip, ip, addr.getAddress().length);
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address: " + cidr, e);
        }
    }

    /**
     * Checks if the given IP address is contained in this range.
     * Returns false if the IP cannot be parsed or is a different address family.
     *
     * @param ip the IP address to check
     * @return true if the IP is in this range, false otherwise
     */
    public boolean contains(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            if (addr.getAddress().length != addressLength) {
                return false;
            }
            BigInteger ipBig = new BigInteger(1, addr.getAddress());
            return ipBig.compareTo(networkAddress) >= 0 && ipBig.compareTo(broadcastAddress) <= 0;
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
