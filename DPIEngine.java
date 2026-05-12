package com.dpi.engine;

import com.dpi.extractor.DNSExtractor;
import com.dpi.extractor.HTTPHostExtractor;
import com.dpi.extractor.SNIExtractor;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.pcap.RawPacket;
import com.dpi.rules.RuleManager;
import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Multi-threaded DPI Engine.
 *
 * Pipeline:
 *   Reader Thread → [LB queues] → LB Threads → [FP queues] → FP Threads
 *                                                           → [output queue]
 *                                                           → Writer Thread → output.pcap
 */
public class DPIEngine {

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------
    public static class Config {
        public int    numLbs    = 2;
        public int    fpsPerLb  = 2;
        public String rulesFile = "";
    }

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------
    private final Config      config;
    private final RuleManager rules;

    private List<LoadBalancer>  lbs;
    private List<FastPath>      fps;
    private TSQueue<PacketJob>  outputQueue;

    // Thread-safe global stats
    private final AtomicLong totalPackets  = new AtomicLong();
    private final AtomicLong totalBytes    = new AtomicLong();
    private final AtomicLong tcpPackets    = new AtomicLong();
    private final AtomicLong udpPackets    = new AtomicLong();
    private final AtomicLong forwarded     = new AtomicLong();
    private final AtomicLong dropped       = new AtomicLong();

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    public DPIEngine(Config config, RuleManager rules) {
        this.config = config;
        this.rules  = rules;

        int totalFps = config.numLbs * config.fpsPerLb;
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.printf( "║              DPI ENGINE v2.0 (Multi-threaded Java)           ║%n");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║  Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d       ║%n",
                config.numLbs, config.fpsPerLb, totalFps);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------
    public boolean process(String inputFile, String outputFile) {

        // 1. Open input
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) return false;

        // 2. Open output
        PcapWriter writer = new PcapWriter();
        if (!writer.open(outputFile)) { reader.close(); return false; }
        writer.writeGlobalHeader(reader.getGlobalHeader());

        // 3. Build pipeline
        int totalFps = config.numLbs * config.fpsPerLb;
        outputQueue  = new TSQueue<>(20_000);
        fps          = new ArrayList<>();
        lbs          = new ArrayList<>();

        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPath(i, rules, outputQueue));
        }
        for (int lb = 0; lb < config.numLbs; lb++) {
            int start = lb * config.fpsPerLb;
            lbs.add(new LoadBalancer(lb, fps.subList(start, start + config.fpsPerLb)));
        }

        // 4. Start all threads
        fps.forEach(FastPath::start);
        lbs.forEach(LoadBalancer::start);

        // 5. Output writer thread
        Thread outputThread = new Thread(() -> {
            while (true) {
                PacketJob pkt = outputQueue.pop(50);
                if (pkt == null) {
                    if (outputQueue.isShutdown() && outputQueue.isEmpty()) break;
                    continue;
                }
                writer.writePacket(pkt.tsSec, pkt.tsUsec, pkt.data);
                forwarded.incrementAndGet();
            }
        }, "OutputWriter");
        outputThread.setDaemon(true);
        outputThread.start();

        // 6. Read and dispatch packets
        System.out.println("[Reader] Processing packets...");
        RawPacket    raw    = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        int pktId = 0;

        while (reader.readNextPacket(raw)) {
            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            // Build PacketJob
            PacketJob job     = new PacketJob();
            job.packetId      = pktId++;
            job.tsSec         = raw.header.tsSec;
            job.tsUsec        = raw.header.tsUsec;
            job.data          = raw.data;
            job.tcpFlags      = parsed.tcpFlags;
            job.payloadOffset = parsed.payloadOffset;
            job.payloadLength = parsed.payloadLength;
            job.tuple         = new FiveTuple(
                    PacketParser.parseIp(parsed.srcIp),
                    PacketParser.parseIp(parsed.destIp),
                    parsed.srcPort, parsed.destPort, parsed.protocol);

            totalPackets.incrementAndGet();
            totalBytes.addAndGet(raw.data.length);
            if (parsed.hasTcp)      tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) udpPackets.incrementAndGet();

            // Dispatch to LB (consistent hash)
            int lbIdx = Math.floorMod(job.tuple.hashCode(), lbs.size());
            lbs.get(lbIdx).getInputQueue().push(job);
        }

        System.out.printf("[Reader] Done reading %d packets%n", pktId);
        reader.close();

        // 7. Drain queues then stop
        sleepMs(500);
        lbs.forEach(LoadBalancer::stop);
        fps.forEach(FastPath::stop);

        // Count dropped (everything that went to FP but wasn't forwarded to outputQueue)
        long fpProcessed = fps.stream().mapToLong(FastPath::getProcessed).sum();
        long fpDropped   = fps.stream().mapToLong(fp -> fp.dropped.get()).sum();
        dropped.set(fpDropped);

        outputQueue.shutdown();
        try { outputThread.join(3000); } catch (InterruptedException ignored) {}

        writer.close();

        // 8. Print report
        printReport();

        System.out.println("\nOutput written to: " + outputFile);
        return true;
    }

    // -----------------------------------------------------------------------
    // Report
    // -----------------------------------------------------------------------
    private void printReport() {
        long total = totalPackets.get();

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Total Packets:       %12d                              ║%n", total);
        System.out.printf( "║ Total Bytes:         %12d                              ║%n", totalBytes.get());
        System.out.printf( "║ TCP Packets:         %12d                              ║%n", tcpPackets.get());
        System.out.printf( "║ UDP Packets:         %12d                              ║%n", udpPackets.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Forwarded:           %12d                              ║%n", forwarded.get());
        System.out.printf( "║ Dropped/Blocked:     %12d                              ║%n", dropped.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                             ║");
        for (LoadBalancer lb : lbs) {
            System.out.printf("║   LB%d dispatched:    %12d                              ║%n",
                    lbs.indexOf(lb), lb.getDispatched());
        }
        for (FastPath fp : fps) {
            System.out.printf("║   FP%d processed:     %12d                              ║%n",
                    fps.indexOf(fp), fp.getProcessed());
        }
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                   APPLICATION BREAKDOWN                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        // Aggregate app counts across all FPs
        Map<AppType, Long> appCounts   = new HashMap<>();
        Map<String, AppType> sniMap    = new LinkedHashMap<>();

        for (FastPath fp : fps) {
            fp.getFlows().values().forEach(f -> {
                appCounts.merge(f.appType, 1L, Long::sum);
                if (!f.sni.isEmpty()) sniMap.putIfAbsent(f.sni, f.appType);
            });
        }

        appCounts.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> {
                    double pct    = total > 0 ? 100.0 * e.getValue() / total : 0;
                    int    barLen = (int)(pct / 5);
                    String bar    = "#".repeat(Math.max(0, barLen));
                    System.out.printf("║ %-15s %8d %5.1f%% %-20s  ║%n",
                            e.getKey().label(), e.getValue(), pct, bar);
                });

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        if (!sniMap.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            sniMap.forEach((sni, app) ->
                    System.out.printf("  - %s -> %s%n", sni, app.label()));
        }
    }

    private static void sleepMs(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }
}