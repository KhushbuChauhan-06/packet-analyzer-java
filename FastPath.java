package com.dpi.engine;

import com.dpi.extractor.DNSExtractor;
import com.dpi.extractor.HTTPHostExtractor;
import com.dpi.extractor.SNIExtractor;
import com.dpi.rules.RuleManager;
import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fast-Path processor thread.
 *
 * Responsibilities:
 *   1. Maintain per-flow state (FlowEntry map)
 *   2. Deep packet inspection — SNI / HTTP Host / DNS extraction
 *   3. Rule evaluation — decide FORWARD or DROP
 *   4. Forward allowed packets to the output queue
 */
public class FastPath implements Runnable {

    private final int       id;
    private final RuleManager rules;
    private final TSQueue<PacketJob> inputQueue;
    private final TSQueue<PacketJob> outputQueue;

    private final Map<FiveTuple, FlowEntry> flows = new HashMap<>();

    private volatile boolean running = false;
    private Thread thread;

    // Stats
    final AtomicLong processed  = new AtomicLong();
    final AtomicLong forwarded  = new AtomicLong();
    final AtomicLong dropped    = new AtomicLong();

    public FastPath(int id, RuleManager rules, TSQueue<PacketJob> outputQueue) {
        this.id          = id;
        this.rules       = rules;
        this.outputQueue = outputQueue;
        this.inputQueue  = new TSQueue<>(10_000);
    }

    public void start() {
        running = true;
        thread  = new Thread(this, "FP-" + id);
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        inputQueue.shutdown();
        try { if (thread != null) thread.join(2000); } catch (InterruptedException ignored) {}
    }

    public TSQueue<PacketJob> getInputQueue() { return inputQueue; }

    @Override
    public void run() {
        while (running) {
            PacketJob pkt = inputQueue.pop(100);
            if (pkt == null) continue;

            processed.incrementAndGet();

            // Get or create flow
            FlowEntry flow = flows.computeIfAbsent(pkt.tuple, t -> {
                FlowEntry f = new FlowEntry();
                f.tuple = t;
                return f;
            });
            flow.packets++;
            flow.bytes += pkt.data.length;

            // Try to classify if not yet done
            if (!flow.classified) {
                classify(pkt, flow);
            }

            // Check blocking rules (re-check in case rules changed)
            if (!flow.blocked) {
                flow.blocked = rules.isBlocked(pkt.tuple.srcIp, flow.appType, flow.sni);
            }

            if (flow.blocked) {
                dropped.incrementAndGet();
            } else {
                forwarded.incrementAndGet();
                outputQueue.push(pkt);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Classification
    // -----------------------------------------------------------------------

    private void classify(PacketJob pkt, FlowEntry flow) {
        // HTTPS → try TLS SNI
        if (pkt.tuple.dstPort == 443 && pkt.payloadLength > 5) {
            String sni = SNIExtractor.extract(pkt.data, pkt.payloadOffset, pkt.payloadLength);
            if (sni != null) {
                flow.sni        = sni;
                flow.appType    = AppType.fromSni(sni);
                flow.classified = true;
                return;
            }
            flow.appType = AppType.HTTPS; // at least we know it's HTTPS
        }

        // HTTP → try Host header
        if (pkt.tuple.dstPort == 80 && pkt.payloadLength > 10) {
            String host = HTTPHostExtractor.extract(pkt.data, pkt.payloadOffset, pkt.payloadLength);
            if (host != null) {
                flow.sni        = host;
                flow.appType    = AppType.fromSni(host);
                flow.classified = true;
                return;
            }
            flow.appType = AppType.HTTP;
        }

        // DNS
        if (pkt.tuple.dstPort == 53 || pkt.tuple.srcPort == 53) {
            String domain = DNSExtractor.extractQuery(pkt.data, pkt.payloadOffset, pkt.payloadLength);
            flow.appType    = AppType.DNS;
            flow.classified = true;
            if (domain != null) flow.sni = domain;
        }
    }

    /** Snapshot of all flows — used by DPIEngine for the final report */
    public Map<FiveTuple, FlowEntry> getFlows() { return flows; }

    public long getProcessed() { return processed.get(); }
}