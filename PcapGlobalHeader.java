package com.dpi.pcap;

/** 24-byte header at the start of every .pcap file */
public class PcapGlobalHeader {
    public int  magicNumber;   // 0xa1b2c3d4
    public int  versionMajor;  // usually 2
    public int  versionMinor;  // usually 4
    public int  thiszone;      // GMT offset (usually 0)
    public int  sigfigs;       // usually 0
    public int  snaplen;       // max captured length
    public int  network;       // link type (1 = Ethernet)
}