package org.jahia.modules.bruteforceloginprotection;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

/**
 * Matches IPv4 and IPv6 addresses against a CIDR block. Replaces Apache Commons
 * {@code SubnetUtils}, which only supports IPv4.
 */
public final class CidrMatcher {

    private final byte[] network;
    private final byte[] mask;
    private final int byteLength;

    public CidrMatcher(String cidr) {
        Objects.requireNonNull(cidr, "cidr must not be null");
        final String trimmed = cidr.trim();
        final int slash = trimmed.indexOf('/');
        final String addressPart;
        final int requestedPrefix;
        if (slash >= 0) {
            addressPart = trimmed.substring(0, slash);
            try {
                requestedPrefix = Integer.parseInt(trimmed.substring(slash + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid prefix length in CIDR: " + cidr, e);
            }
        } else {
            addressPart = trimmed;
            requestedPrefix = -1;
        }
        final InetAddress address;
        try {
            address = InetAddress.getByName(addressPart);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address in CIDR: " + cidr, e);
        }
        final byte[] bytes = address.getAddress();
        this.byteLength = bytes.length;
        final int prefixLength = requestedPrefix < 0 ? byteLength * 8 : requestedPrefix;
        if (prefixLength < 0 || prefixLength > byteLength * 8) {
            throw new IllegalArgumentException("Invalid prefix length in CIDR: " + cidr);
        }
        this.mask = buildMask(byteLength, prefixLength);
        this.network = new byte[byteLength];
        for (int i = 0; i < byteLength; i++) {
            network[i] = (byte) (bytes[i] & mask[i]);
        }
    }

    public boolean matches(String address) {
        if (address == null) {
            return false;
        }
        final byte[] candidate;
        try {
            candidate = InetAddress.getByName(address.trim()).getAddress();
        } catch (UnknownHostException e) {
            return false;
        }
        if (candidate.length != byteLength) {
            return false;
        }
        for (int i = 0; i < byteLength; i++) {
            if ((candidate[i] & mask[i]) != network[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] buildMask(int byteLength, int prefixLength) {
        final byte[] result = new byte[byteLength];
        for (int i = 0; i < byteLength; i++) {
            final int bitsLeft = prefixLength - i * 8;
            if (bitsLeft >= 8) {
                result[i] = (byte) 0xFF;
            } else if (bitsLeft > 0) {
                result[i] = (byte) (0xFF << (8 - bitsLeft));
            } else {
                result[i] = 0;
            }
        }
        return result;
    }
}
