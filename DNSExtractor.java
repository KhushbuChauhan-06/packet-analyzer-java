package com.dpi.extractor;

import static com.dpi.parser.PacketParser.u8;
import static com.dpi.parser.PacketParser.u16be;

/** Extracts the queried domain name from a DNS request packet */
public class DNSExtractor {

    public static String extractQuery(byte[] data, int off, int len) {
        if (len < 12) return null;
        // QR bit = 0 means query
        if ((u8(data, off + 2) & 0x80) != 0) return null;
        // QDCOUNT must be > 0
        if (u16be(data, off + 4) == 0) return null;

        int cursor = off + 12;
        StringBuilder domain = new StringBuilder();
        while (cursor < off + len) {
            int labelLen = u8(data, cursor++);
            if (labelLen == 0) break;
            if (labelLen > 63) break; // compression pointer
            if (cursor + labelLen > off + len) break;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, cursor, labelLen));
            cursor += labelLen;
        }
        return domain.length() > 0 ? domain.toString() : null;
    }
}