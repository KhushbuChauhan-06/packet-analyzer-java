package com.dpi.parser;

import com.dpi.pcap.RawPacket;

/**
 * Parses raw packet bytes into structured protocol fields.
 *
 * Packet structure (Russian-doll style):
 *   [Ethernet 14B][IP 20B+][TCP/UDP 20/8B][Payload]
 */
public class PacketParser {

    // EtherType constants
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // Protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // TCP flags
    public static final int FLAG_FIN = 0x01;
    public static final int FLAG_SYN = 0x02;
    public static final int FLAG_RST = 0x04;
    public static final int FLAG_PSH = 0x08;
    public static final int FLAG_ACK = 0x10;
    public static final int FLAG_URG = 0x20;

    /** Parse a raw packet. Returns false if the packet is too short or malformed. */
    public static boolean parse(RawPacket raw, ParsedPacket out) {
        out.timestampSec  = raw.header.tsSec;
        out.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int    len  = data.length;
        int    off  = 0;

        // ---- Ethernet (14 bytes) ----
        if (len < 14) return false;
        out.destMac   = macToString(data, 0);
        out.srcMac    = macToString(data, 6);
        out.etherType = u16be(data, 12);
        off = 14;

        if (out.etherType != ETHERTYPE_IPV4) {
            // We only fully parse IPv4 for now
            return true; // still "parsed", just no IP layer
        }

        // ---- IPv4 ----
        if (len < off + 20) return false;
        int versionIhl = u8(data, off);
        out.ipVersion  = (versionIhl >> 4) & 0x0F;
        if (out.ipVersion != 4) return false;
        int ipHdrLen  = (versionIhl & 0x0F) * 4;
        if (ipHdrLen < 20 || len < off + ipHdrLen) return false;

        out.ttl      = u8(data, off + 8);
        out.protocol = u8(data, off + 9);
        out.srcIp    = ipToString(data, off + 12);
        out.destIp   = ipToString(data, off + 16);
        out.hasIp    = true;
        off += ipHdrLen;

        // ---- TCP ----
        if (out.protocol == PROTO_TCP) {
            if (len < off + 20) return false;
            out.srcPort   = u16be(data, off);
            out.destPort  = u16be(data, off + 2);
            out.seqNumber = u32be(data, off + 4);
            out.ackNumber = u32be(data, off + 8);
            int tcpHdrLen = ((u8(data, off + 12) >> 4) & 0x0F) * 4;
            if (tcpHdrLen < 20 || len < off + tcpHdrLen) return false;
            out.tcpFlags  = u8(data, off + 13);
            out.hasTcp    = true;
            off += tcpHdrLen;

        // ---- UDP ----
        } else if (out.protocol == PROTO_UDP) {
            if (len < off + 8) return false;
            out.srcPort  = u16be(data, off);
            out.destPort = u16be(data, off + 2);
            out.hasUdp   = true;
            off += 8;
        }

        out.payloadOffset = off;
        out.payloadLength = len - off;
        return true;
    }

    // -----------------------------------------------------------------------
    // String helpers
    // -----------------------------------------------------------------------

    public static String macToString(byte[] data, int off) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                u8(data,off), u8(data,off+1), u8(data,off+2),
                u8(data,off+3), u8(data,off+4), u8(data,off+5));
    }

    public static String ipToString(byte[] data, int off) {
        return String.format("%d.%d.%d.%d",
                u8(data,off), u8(data,off+1), u8(data,off+2), u8(data,off+3));
    }

    /** Parse dotted-decimal IP string to 32-bit int (network order: first octet in lowest byte) */
    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0;
        int r = 0;
        for (int i = 0; i < 4; i++) {
            r |= (Integer.parseInt(parts[i]) & 0xFF) << (i * 8);
        }
        return r;
    }

    public static String protocolToString(int proto) {
        return switch (proto) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP  -> "TCP";
            case PROTO_UDP  -> "UDP";
            default         -> "Unknown(" + proto + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & FLAG_SYN) != 0) sb.append("SYN ");
        if ((flags & FLAG_ACK) != 0) sb.append("ACK ");
        if ((flags & FLAG_FIN) != 0) sb.append("FIN ");
        if ((flags & FLAG_RST) != 0) sb.append("RST ");
        if ((flags & FLAG_PSH) != 0) sb.append("PSH ");
        if ((flags & FLAG_URG) != 0) sb.append("URG ");
        return sb.isEmpty() ? "none" : sb.toString().trim();
    }

    // -----------------------------------------------------------------------
    // Low-level read helpers (big-endian network byte order)
    // -----------------------------------------------------------------------

    public static int u8(byte[] d, int i)   { return d[i] & 0xFF; }
    public static int u16be(byte[] d, int i) { return ((d[i] & 0xFF) << 8) | (d[i+1] & 0xFF); }
    public static long u32be(byte[] d, int i) {
        return ((long)(d[i]   & 0xFF) << 24) | ((long)(d[i+1] & 0xFF) << 16) |
               ((long)(d[i+2] & 0xFF) << 8 ) |  (long)(d[i+3] & 0xFF);
    }
}