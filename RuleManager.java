package com.dpi.rules;

import com.dpi.types.AppType;
import com.dpi.parser.PacketParser;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Thread-safe rule manager.  Supports blocking by IP, AppType, domain substring, or port.
 */
public class RuleManager {

    private final Set<Integer>  blockedIps      = ConcurrentHashMap.newKeySet();
    private final Set<AppType>  blockedApps     = ConcurrentHashMap.newKeySet();
    private final List<String>  blockedDomains  = new CopyOnWriteArrayList<>();
    private final Set<Integer>  blockedPorts    = ConcurrentHashMap.newKeySet();

    // ---- IP ----

    public void blockIp(String ip) {
        int addr = PacketParser.parseIp(ip);
        blockedIps.add(addr);
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    public void unblockIp(String ip) { blockedIps.remove(PacketParser.parseIp(ip)); }

    public boolean isIpBlocked(int ip) { return blockedIps.contains(ip); }

    // ---- App ----

    public void blockApp(String name) {
        for (AppType a : AppType.values()) {
            if (a.label().equalsIgnoreCase(name)) {
                blockedApps.add(a);
                System.out.println("[Rules] Blocked app: " + name);
                return;
            }
        }
        System.err.println("[Rules] Unknown app: " + name);
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
        System.out.println("[Rules] Blocked app: " + app.label());
    }

    public boolean isAppBlocked(AppType app) { return blockedApps.contains(app); }

    // ---- Domain (substring match) ----

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public boolean isDomainBlocked(String sni) {
        if (sni == null || sni.isEmpty()) return false;
        String lower = sni.toLowerCase();
        for (String d : blockedDomains) {
            if (d.startsWith("*.")) {
                String suffix = d.substring(1); // ".example.com"
                if (lower.endsWith(suffix) || lower.equals(d.substring(2))) return true;
            } else {
                if (lower.contains(d)) return true;
            }
        }
        return false;
    }

    // ---- Port ----

    public void blockPort(int port) { blockedPorts.add(port); }

    public boolean isPortBlocked(int port) { return blockedPorts.contains(port); }

    // ---- Combined check ----

    public record BlockReason(String type, String detail) {}

    public BlockReason shouldBlock(int srcIp, int dstPort, AppType app, String sni) {
        if (isIpBlocked(srcIp))       return new BlockReason("IP",     ipStr(srcIp));
        if (isPortBlocked(dstPort))   return new BlockReason("PORT",   String.valueOf(dstPort));
        if (isAppBlocked(app))        return new BlockReason("APP",    app.label());
        if (isDomainBlocked(sni))     return new BlockReason("DOMAIN", sni);
        return null;
    }

    // ---- Simple check (used by single-threaded path) ----
    public boolean isBlocked(int srcIp, AppType app, String sni) {
        return shouldBlock(srcIp, 0, app, sni) != null;
    }

    // ---- Stats ----
    public int countIps()     { return blockedIps.size(); }
    public int countApps()    { return blockedApps.size(); }
    public int countDomains() { return blockedDomains.size(); }
    public int countPorts()   { return blockedPorts.size(); }

    // ---- Persistence ----

    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String section = "", line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) { section = line; continue; }
                switch (section) {
                    case "[BLOCKED_IPS]"     -> blockIp(line);
                    case "[BLOCKED_APPS]"    -> blockApp(line);
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]"   -> blockPort(Integer.parseInt(line));
                }
            }
            System.out.println("[Rules] Loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[Rules] Cannot load: " + e.getMessage());
            return false;
        }
    }

    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(filename)) {
            pw.println("[BLOCKED_IPS]");
            blockedIps.forEach(ip -> pw.println(ipStr(ip)));
            pw.println("\n[BLOCKED_APPS]");
            blockedApps.forEach(a -> pw.println(a.label()));
            pw.println("\n[BLOCKED_DOMAINS]");
            blockedDomains.forEach(pw::println);
            pw.println("\n[BLOCKED_PORTS]");
            blockedPorts.forEach(pw::println);
            System.out.println("[Rules] Saved to: " + filename);
            return true;
        } catch (IOException e) { return false; }
    }

    private static String ipStr(int ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
    }
}