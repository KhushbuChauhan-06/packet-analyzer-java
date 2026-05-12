package com.dpi.extractor;

import static com.dpi.parser.PacketParser.u8;

/** Extracts the HTTP Host header from unencrypted HTTP/1.x requests */
public class HTTPHostExtractor {

    private static final byte[][] METHODS = {
        "GET ".getBytes(), "POST".getBytes(), "PUT ".getBytes(),
        "HEAD".getBytes(), "DELE".getBytes(), "PATC".getBytes(), "OPTI".getBytes()
    };

    public static String extract(byte[] data, int off, int len) {
        if (len < 10) return null;

        // Verify it's an HTTP request
        boolean isHttp = false;
        for (byte[] m : METHODS) {
            if (off + 4 <= off + len &&
                data[off] == m[0] && data[off+1] == m[1] &&
                data[off+2] == m[2] && data[off+3] == m[3]) {
                isHttp = true; break;
            }
        }
        if (!isHttp) return null;

        // Find "Host:" (case-insensitive)
        for (int i = off; i < off + len - 5; i++) {
            if ((data[i] == 'H' || data[i] == 'h') &&
                (data[i+1] == 'o' || data[i+1] == 'O') &&
                (data[i+2] == 's' || data[i+2] == 'S') &&
                (data[i+3] == 't' || data[i+3] == 'T') &&
                data[i+4] == ':') {

                int start = i + 5;
                // skip whitespace
                while (start < off + len && (data[start] == ' ' || data[start] == '\t')) start++;
                int end = start;
                while (end < off + len && data[end] != '\r' && data[end] != '\n') end++;
                if (end > start) {
                    String host = new String(data, start, end - start);
                    int colon = host.indexOf(':');
                    return colon >= 0 ? host.substring(0, colon) : host;
                }
            }
        }
        return null;
    }
}