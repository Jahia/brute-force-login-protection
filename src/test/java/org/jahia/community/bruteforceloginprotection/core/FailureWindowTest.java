package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

public class FailureWindowTest {

    @Test
    public void emptyWindowReportsZeroSizeAndNullEnds() {
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        assertThat(w.size()).isZero();
        assertThat(w.oldest()).isNull();
        assertThat(w.newest()).isNull();
    }

    @Test
    public void addIncrementsSizeAndUpdatesEnds() {
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        w.add(100L);
        w.add(200L);
        w.add(300L);
        assertThat(w.size()).isEqualTo(3);
        assertThat(w.oldest()).isEqualTo(100L);
        assertThat(w.newest()).isEqualTo(300L);
    }

    @Test
    public void pruneRemovesEntriesOlderThanCutoff() {
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        w.add(100L);
        w.add(200L);
        w.add(300L);
        w.prune(250L);
        assertThat(w.size()).isEqualTo(1);
        assertThat(w.oldest()).isEqualTo(300L);
    }

    @Test
    public void pruneCutoffMatchingKeepsEqualValues() {
        // prune uses peekFirst() < cutoffMs, so equal stays
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        w.add(100L);
        w.add(200L);
        w.prune(200L);
        assertThat(w.size()).isEqualTo(1);
        assertThat(w.oldest()).isEqualTo(200L);
    }

    @Test
    public void clearEmptiesWindow() {
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        w.add(100L);
        w.clear();
        assertThat(w.size()).isZero();
    }

    @Test
    public void getIpAndJailNameAreRetained() {
        FailureWindow w = new FailureWindow("9.9.9.9", "ssh");
        assertThat(w.getIp()).isEqualTo("9.9.9.9");
        assertThat(w.getJailName()).isEqualTo("ssh");
    }

    @Test
    public void serializationRoundTripPreservesState() throws Exception {
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        w.add(11L);
        w.add(22L);
        w.add(33L);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(w);
        }
        FailureWindow copy;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            copy = (FailureWindow) ois.readObject();
        }
        assertThat(copy.getIp()).isEqualTo("1.2.3.4");
        assertThat(copy.getJailName()).isEqualTo("login");
        assertThat(copy.size()).isEqualTo(3);
        assertThat(copy.oldest()).isEqualTo(11L);
        assertThat(copy.newest()).isEqualTo(33L);
    }

    // -------------------------------------------------------------------------------------------
    // F1 residual — serialize/deserialize AFTER prune() (the round-trip above serializes
    // un-pruned raw state; this covers the specific claim that pruned state survives the
    // round-trip, not merely raw state).
    // -------------------------------------------------------------------------------------------

    @Test
    public void serializationRoundTripAfterPrunePreservesPrunedState() throws Exception {
        FailureWindow w = new FailureWindow("1.2.3.4", "login");
        w.add(100L);
        w.add(200L);
        w.add(300L);
        w.prune(250L); // evicts 100L and 200L, leaving only 300L

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(w);
        }
        FailureWindow copy;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            copy = (FailureWindow) ois.readObject();
        }
        assertThat(copy.size()).isEqualTo(1);
        assertThat(copy.oldest()).isEqualTo(300L);
        assertThat(copy.newest()).isEqualTo(300L);
    }
}
