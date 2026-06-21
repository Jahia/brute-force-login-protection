package org.jahia.community.bruteforceloginprotection.core;

import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;

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

    /** Returns an unmodifiable snapshot of the timestamps; callers cannot mutate internal state. */
    public List<Long> getTimestamps() { return Collections.unmodifiableList(new ArrayList<>(timestamps)); }

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
