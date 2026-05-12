package com.dpi.pcap;

import java.io.*;
import java.nio.ByteOrder;

/**
 * Reads libpcap capture files (.pcap).
 * Handles both little-endian (standard) and big-endian files automatically.
 */
public class PcapReader implements Closeable {

    // When Java (big-endian) reads the 4 magic bytes:
    //   file bytes d4 c3 b2 a1  (LE file) → Java int = 0xd4c3b2a1  → LE file
    //   file bytes a1 b2 c3 d4  (BE file) → Java int = 0xa1b2c3d4  → BE file
    private static final long MAGIC_READ_FROM_LE_FILE = 0xd4c3b2a1L;
    private static final long MAGIC_READ_FROM_BE_FILE = 0xa1b2c3d4L;

    private DataInputStream   dis;
    private PcapGlobalHeader  globalHeader;
    private boolean           littleEndian = true; // most PCAP files are LE

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    public boolean open(String filename) {
        try {
            dis = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));

            // Read magic in big-endian (Java default)
            long magic = Integer.toUnsignedLong(dis.readInt());

            if (magic == MAGIC_READ_FROM_LE_FILE) {
                littleEndian = true;            // most common case
            } else if (magic == MAGIC_READ_FROM_BE_FILE) {
                littleEndian = false;           // rare big-endian capture
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magic);
                return false;
            }

            globalHeader = new PcapGlobalHeader();
            globalHeader.magicNumber  = (int) magic;
            globalHeader.versionMajor = readU16();
            globalHeader.versionMinor = readU16();
            globalHeader.thiszone     = readI32();
            globalHeader.sigfigs      = readI32();
            globalHeader.snaplen      = readI32();
            globalHeader.network      = readI32();

            System.out.printf("Opened PCAP file: %s%n", filename);
            System.out.printf("  Version:   %d.%d%n", globalHeader.versionMajor, globalHeader.versionMinor);
            System.out.printf("  Snaplen:   %d bytes%n", globalHeader.snaplen);
            System.out.printf("  Link type: %d%s%n", globalHeader.network,
                    globalHeader.network == 1 ? " (Ethernet)" : "");
            return true;

        } catch (IOException e) {
            System.err.println("Error opening PCAP file: " + e.getMessage());
            return false;
        }
    }

    public boolean readNextPacket(RawPacket packet) {
        try {
            packet.header.tsSec   = Integer.toUnsignedLong(readI32());
            packet.header.tsUsec  = Integer.toUnsignedLong(readI32());
            packet.header.inclLen = readI32();
            packet.header.origLen = readI32();

            int len = packet.header.inclLen;
            if (len < 0 || len > 65535) {
                System.err.println("Error: Invalid packet length: " + len);
                return false;
            }

            packet.data = new byte[len];
            dis.readFully(packet.data);
            return true;

        } catch (EOFException e) {
            return false; // normal end
        } catch (IOException e) {
            System.err.println("Error reading packet: " + e.getMessage());
            return false;
        }
    }

    public PcapGlobalHeader getGlobalHeader() { return globalHeader; }
    public boolean isLittleEndian()            { return littleEndian; }

    @Override
    public void close() {
        if (dis != null) try { dis.close(); } catch (IOException ignored) {}
    }

    // -----------------------------------------------------------------------
    // Byte-order-aware reads
    // -----------------------------------------------------------------------

    /** Read 4 bytes and return as signed int in host byte order */
    private int readI32() throws IOException {
        int v = dis.readInt(); // big-endian read
        return littleEndian ? Integer.reverseBytes(v) : v;
    }

    /** Read 2 bytes and return as unsigned int (0–65535) in host byte order */
    public int readU16() throws IOException {
        short s = dis.readShort();
        if (littleEndian) s = Short.reverseBytes(s);
        return Short.toUnsignedInt(s);
    }
}