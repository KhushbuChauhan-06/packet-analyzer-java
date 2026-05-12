package com.dpi.types;

/** Application classification types detected via SNI / HTTP Host / port */
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC,
    GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM,
    NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP,
    TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE;

    /** Human-readable name */
    public String label() {
        return switch (this) {
            case UNKNOWN    -> "Unknown";
            case HTTP       -> "HTTP";
            case HTTPS      -> "HTTPS";
            case DNS        -> "DNS";
            case TLS        -> "TLS";
            case QUIC       -> "QUIC";
            case GOOGLE     -> "Google";
            case FACEBOOK   -> "Facebook";
            case YOUTUBE    -> "YouTube";
            case TWITTER    -> "Twitter/X";
            case INSTAGRAM  -> "Instagram";
            case NETFLIX    -> "Netflix";
            case AMAZON     -> "Amazon";
            case MICROSOFT  -> "Microsoft";
            case APPLE      -> "Apple";
            case WHATSAPP   -> "WhatsApp";
            case TELEGRAM   -> "Telegram";
            case TIKTOK     -> "TikTok";
            case SPOTIFY    -> "Spotify";
            case ZOOM       -> "Zoom";
            case DISCORD    -> "Discord";
            case GITHUB     -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
        };
    }

    /** Map an SNI hostname to an AppType */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be")) return YOUTUBE;
        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com") || s.contains("meta.com")) return FACEBOOK;
        if (s.contains("instagram") || s.contains("cdninstagram")) return INSTAGRAM;
        if (s.contains("whatsapp") || s.contains("wa.me")) return WHATSAPP;
        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis") || s.contains("ggpht")) return GOOGLE;
        if (s.contains("twitter") || s.contains("twimg") ||
            s.equals("x.com") || s.endsWith(".x.com") ||
            s.equals("t.co")  || s.endsWith(".t.co"))  return TWITTER;
        if (s.contains("netflix") || s.contains("nflx")) return NETFLIX;
        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("cloudfront") || s.contains("aws.")) return AMAZON;
        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office") ||
            s.contains("azure") || s.contains("live.com") || s.contains("outlook") || s.contains("bing")) return MICROSOFT;
        if (s.contains("apple") || s.contains("icloud") || s.contains("mzstatic") || s.contains("itunes")) return APPLE;
        if (s.contains("telegram") || s.equals("t.me")) return TELEGRAM;
        if (s.contains("tiktok") || s.contains("bytedance") || s.contains("musical.ly")) return TIKTOK;
        if (s.contains("spotify") || s.contains("scdn.co")) return SPOTIFY;
        if (s.contains("zoom")) return ZOOM;
        if (s.contains("discord") || s.contains("discordapp")) return DISCORD;
        if (s.contains("github") || s.contains("githubusercontent")) return GITHUB;
        if (s.contains("cloudflare") || s.contains("cf-")) return CLOUDFLARE;

        return HTTPS; // SNI present but unrecognized → at least it's TLS
    }
}