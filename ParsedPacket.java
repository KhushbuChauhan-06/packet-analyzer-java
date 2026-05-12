package com.dpi.parser;

/** All protocol fields extracted from a raw packet in human-readable form */
public class ParsedPacket {
    // Timestamps
    public long   timestampSec;
    public long   timestampUsec;

    // Ethernet
    public String srcMac;
    public String destMac;
    public int    etherType;    // 0x0800 = IPv4

    // IP
    public boolean hasIp   = false;
    public int     ipVersion;
    public String  srcIp;
    public String  destIp;
    public int     protocol;   // 6=TCP, 17=UDP
    public int     ttl;

    // Transport
    public boolean hasTcp  = false;
    public boolean hasUdp  = false;
    public int     srcPort;
    public int     destPort;

    // TCP specific
    public int  tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload
    public int    payloadLength;
    public int    payloadOffset; // offset into RawPacket.data
}