package com.dpi.types;

import java.util.Objects;

/**
 * A 5-tuple uniquely identifies a network connection/flow.
 * IPs are stored in "little-endian packed" form matching parseIp() in PacketParser.
 */
public final class FiveTuple {
    public final int  srcIp;
    public final int  dstIp;
    public final int  srcPort;
    public final int  dstPort;
    public final int  protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Reverse the tuple (for bidirectional matching) */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Combine all fields using the same mix as the C++ FiveTupleHash
        long h = 0;
        h ^= Integer.toUnsignedLong(srcIp)  * 0x9e3779b9L + 0x6b37ec59L;
        h ^= Integer.toUnsignedLong(dstIp)  * 0x9e3779b9L + 0x6b37ec59L + (h << 6) + (h >>> 2);
        h ^= srcPort  + 0x9e3779b9L + (h << 6) + (h >>> 2);
        h ^= dstPort  + 0x9e3779b9L + (h << 6) + (h >>> 2);
        h ^= protocol + 0x9e3779b9L + (h << 6) + (h >>> 2);
        return (int) h;
    }

    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d (%s)",
                ipStr(srcIp), srcPort, ipStr(dstIp), dstPort,
                protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?");
    }

    private static String ipStr(int ip) {
        return String.format("%d.%d.%d.%d",
                ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    }
}