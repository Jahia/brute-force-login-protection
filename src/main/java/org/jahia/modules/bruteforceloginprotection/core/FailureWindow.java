package org.jahia.modules.bruteforceloginprotection.core;

import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.Deque;

public class FailureWindow implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String ip;
    private final String jailName;
    private final Deque<Long> timestamps;

    public FailureWindow(String ip, String jailName) {
        this.ip = ip;
        this.jailName = jailName;
        this.timestamps = new ArrayDeque<>();
    }

    public String getIp() { return ip; }
    public String getJailName() { return jailName; }
    public Deque<Long> getTimestamps() { return timestamps; }

    public void add(long ts) {
        timestamps.addLast(ts);
    }

    public int size() {
        return timestamps.size();
    }

    public Long oldest() {
        return timestamps.isEmpty() ? null : timestamps.peekFirst();
    }

    public Long newest() {
        return timestamps.isEmpty() ? null : timestamps.peekLast();
    }

    public void prune(long cutoffMs) {
        while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoffMs) {
            timestamps.pollFirst();
        }
    }

    public void clear() {
        timestamps.clear();
    }
}
