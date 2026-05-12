package com.dpi.pcap;

/** 16-byte header preceding each captured packet in a .pcap file */
public class PcapPacketHeader {
    public long tsSec;   // timestamp seconds  (uint32 → long)
    public long tsUsec;  // timestamp micros    (uint32 → long)
    public int  inclLen; // bytes saved in file (uint32 → int, always ≤ 65535)
    public int  origLen; // original packet size
}