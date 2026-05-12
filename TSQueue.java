package com.dpi.engine;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Bounded, thread-safe queue for passing PacketJobs between pipeline stages.
 * Equivalent to the C++ TSQueue template.
 */
public class TSQueue<T> {

    private final LinkedBlockingQueue<T> queue;
    private final AtomicBoolean          shutdown = new AtomicBoolean(false);

    public TSQueue(int capacity) {
        queue = new LinkedBlockingQueue<>(capacity);
    }

    /** Blocking push — waits if full */
    public void push(T item) {
        if (shutdown.get()) return;
        try {
            while (!shutdown.get()) {
                if (queue.offer(item, 100, TimeUnit.MILLISECONDS)) return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Timed pop — returns null on timeout or shutdown */
    public T pop(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** Signal all waiting threads to exit */
    public void shutdown() {
        shutdown.set(true);
    }

    public boolean isShutdown() { return shutdown.get(); }
    public int     size()       { return queue.size(); }
    public boolean isEmpty()    { return queue.isEmpty(); }
}