package com.dpi.types;

/** A self-contained packet passed through the processing pipeline queues */
public class PacketJob {
    public int       packetId;
    public FiveTuple tuple;
    public byte[]    data;
    public int       payloadOffset;
    public int       payloadLength;
    public int       tcpFlags;
    public long      tsSec;
    public long      tsUsec;
}