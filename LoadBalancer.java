package com.dpi.engine;

import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load-Balancer thread.
 *
 * Receives packets from the reader, hashes the 5-tuple, and dispatches
 * to one of its assigned FastPath threads for consistent flow-to-thread affinity.
 */
public class LoadBalancer implements Runnable {

    private final int               id;
    private final List<FastPath>    fastPaths;
    private final TSQueue<PacketJob> inputQueue;

    private volatile boolean running = false;
    private Thread thread;

    final AtomicLong dispatched = new AtomicLong();

    public LoadBalancer(int id, List<FastPath> fastPaths) {
        this.id         = id;
        this.fastPaths  = fastPaths;
        this.inputQueue = new TSQueue<>(10_000);
    }

    public void start() {
        running = true;
        thread  = new Thread(this, "LB-" + id);
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

            // Consistent hash → same flow always goes to same FP
            int fpIdx = Math.floorMod(pkt.tuple.hashCode(), fastPaths.size());
            fastPaths.get(fpIdx).getInputQueue().push(pkt);
            dispatched.incrementAndGet();
        }
    }

    public long getDispatched() { return dispatched.get(); }
}