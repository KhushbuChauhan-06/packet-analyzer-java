package com.dpi.extractor;

import static com.dpi.parser.PacketParser.*;

/**
 * Extracts the SNI (Server Name Indication) from a TLS 1.x Client Hello message.
 *
 * TLS record layout (simplified):
 *   [0]      Content-Type  = 0x16 (Handshake)
 *   [1-2]    TLS version   = 0x0301..0x0304
 *   [3-4]    Record length
 *   [5]      Handshake-Type = 0x01 (Client Hello)
 *   [6-8]    Handshake length (3 bytes)
 *   [9-10]   Client version
 *   [11-42]  Random (32 bytes)
 *   [43]     Session-ID length (N)
 *   ...      Session ID
 *   ...      Cipher suites length + list
 *   ...      Compression methods
 *   ...      Extensions length + list
 *             └─ Extension type 0x0000 = SNI
 */
public class SNIExtractor {

    private static final int CONTENT_HANDSHAKE = 0x16;
    private static final int TYPE_CLIENT_HELLO = 0x01;
    private static final int EXT_SNI           = 0x0000;
    private static final int SNI_HOST_NAME     = 0x00;

    /** Returns the SNI hostname, or null if not found / not a Client Hello */
    public static String extract(byte[] data, int off, int len) {
        if (len < 9) return null;

        // TLS record header
        if (u8(data, off) != CONTENT_HANDSHAKE) return null;
        int tlsVer = u16be(data, off + 1);
        if (tlsVer < 0x0300 || tlsVer > 0x0304) return null;

        // Handshake header at off+5
        if (u8(data, off + 5) != TYPE_CLIENT_HELLO) return null;

        int cursor = off + 5 + 4;  // skip HS-type (1) + HS-length (3)

        // Client version (2 bytes)
        cursor += 2;
        // Random (32 bytes)
        cursor += 32;

        if (cursor >= off + len) return null;

        // Session ID
        int sidLen = u8(data, cursor++);
        cursor += sidLen;

        if (cursor + 2 > off + len) return null;
        // Cipher suites
        int csLen = u16be(data, cursor); cursor += 2 + csLen;

        if (cursor >= off + len) return null;
        // Compression methods
        int compLen = u8(data, cursor++);
        cursor += compLen;

        // Extensions
        if (cursor + 2 > off + len) return null;
        int extTotal = u16be(data, cursor); cursor += 2;
        int extEnd = cursor + extTotal;
        if (extEnd > off + len) extEnd = off + len;

        while (cursor + 4 <= extEnd) {
            int extType = u16be(data, cursor);
            int extLen  = u16be(data, cursor + 2);
            cursor += 4;
            if (cursor + extLen > extEnd) break;

            if (extType == EXT_SNI && extLen >= 5) {
                // sniListLen (2) | sniType (1) | sniLen (2) | sniValue
                int sniType = u8(data, cursor + 2);
                if (sniType == SNI_HOST_NAME) {
                    int sniLen = u16be(data, cursor + 3);
                    if (sniLen <= extLen - 5) {
                        return new String(data, cursor + 5, sniLen);
                    }
                }
            }
            cursor += extLen;
        }
        return null;
    }

    /** Convenience: pass entire packet data with offsets */
    public static String extract(byte[] data, int payloadOff, int payloadLen, int dummy) {
        return extract(data, payloadOff, payloadLen);
    }
}