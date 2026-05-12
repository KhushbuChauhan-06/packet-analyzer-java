package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets to a libpcap output file.
 * Always writes in little-endian format (standard for most tools).
 */
public class PcapWriter implements Closeable {

    private DataOutputStream dos;
    private final Object writeLock = new Object();

    public boolean open(String filename) {
        try {
            dos = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
            return true;
        } catch (IOException e) {
            System.err.println("Error opening output PCAP: " + e.getMessage());
            return false;
        }
    }

    /** Write the PCAP global header (24 bytes, little-endian) */
    public synchronized boolean writeGlobalHeader(PcapGlobalHeader hdr) {
        try {
            writeU32(0xa1b2c3d4L);              // magic (LE)
            writeU16(hdr.versionMajor);
            writeU16(hdr.versionMinor);
            writeI32(hdr.thiszone);
            writeU32(Integer.toUnsignedLong(hdr.sigfigs));
            writeU32(Integer.toUnsignedLong(hdr.snaplen));
            writeU32(Integer.toUnsignedLong(hdr.network));
            dos.flush();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Write a complete packet (16-byte header + data) */
    public synchronized void writePacket(long tsSec, long tsUsec, byte[] data) {
        try {
            writeU32(tsSec);
            writeU32(tsUsec);
            writeU32(Integer.toUnsignedLong(data.length));
            writeU32(Integer.toUnsignedLong(data.length));
            dos.write(data);
        } catch (IOException e) {
            System.err.println("Error writing packet: " + e.getMessage());
        }
    }

    public synchronized void flush() {
        try { if (dos != null) dos.flush(); } catch (IOException ignored) {}
    }

    @Override
    public void close() {
        flush();
        if (dos != null) try { dos.close(); } catch (IOException ignored) {}
    }

    // --- little-endian helpers ---

    private void writeU32(long v) throws IOException {
        dos.writeByte((int)(v & 0xFF));
        dos.writeByte((int)((v >> 8) & 0xFF));
        dos.writeByte((int)((v >> 16) & 0xFF));
        dos.writeByte((int)((v >> 24) & 0xFF));
    }

    private void writeI32(int v) throws IOException {
        writeU32(Integer.toUnsignedLong(v));
    }

    private void writeU16(int v) throws IOException {
        dos.writeByte(v & 0xFF);
        dos.writeByte((v >> 8) & 0xFF);
    }
}