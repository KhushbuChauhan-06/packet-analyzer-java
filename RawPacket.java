package com.dpi.pcap;

/** A single captured packet as read from disk */
public class RawPacket {
    public PcapPacketHeader header = new PcapPacketHeader();
    public byte[]           data;
}