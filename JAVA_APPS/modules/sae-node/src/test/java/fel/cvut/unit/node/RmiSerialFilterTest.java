package fel.cvut.unit.node;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.node.Address;
import fel.cvut.node.interNodeCommunication.RmiSerialFilter;
import fel.cvut.node.pairlock.PairLockLostException;
import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.PriorityQueue;
import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.time.Instant;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The RMI filters accept exactly the NodeCommands argument types and reply types. */
@Tag("unit")
class RmiSerialFilterTest {

    @Test
    void acceptsEveryArgumentShapeNodeCommandsUses() throws Exception {
        assertEquals("x", roundTrip("x"));
        Address address = (Address) roundTrip(new Address("127.0.0.1", 2010));
        assertEquals(2010, address.port);
        ClientRecord.ClientHeader header = SaeFixtures.header(HASH_1, HASH_2, ORIGIN_SAE);
        assertEquals(header, roundTrip(header));
        for (List<String> payload : List.<List<String>>of(
                List.<String>of(),
                List.of("key-1"),
                List.of("key-1", "key-2", "key-3"),
                new ArrayList<>(List.of("key-1")),
                Arrays.asList("key-1", "key-2"),
                Collections.unmodifiableList(new ArrayList<>(List.of("key-1"))),
                Collections.singletonList("key-1"),
                Collections.emptyList())) {
            ClientRecord record = SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, payload);
            assertEquals(payload, ((ClientRecord) roundTrip(record)).getPayload());
        }
    }

    @Test
    void rejectsTypesOutsideTheAllowlist() {
        assertRejected(new HashMap<String, String>());
        assertRejected(new PriorityQueue<String>());
        assertRejected(new java.util.Date());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void rejectsDisallowedObjectSmuggledInsidePayload() {
        List raw = new ArrayList();
        raw.add(new HashMap<String, String>());
        assertRejected(SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, raw));
    }

    @Test
    void enforcesDepthAndArrayLimits() {
        List<Object> deep = new ArrayList<>();
        List<Object> cursor = deep;
        for (int i = 0; i < 12; i++) {
            List<Object> next = new ArrayList<>();
            cursor.add(next);
            cursor = next;
        }
        assertRejected(deep);
        assertRejected(List.copyOf(Collections.nCopies(20_000, "k")));
    }

    @Test
    void repliesAcceptEveryReturnTypeAndCallFailure() throws Exception {
        AtomicRecordStateMap.RecordMetadata metadata = new AtomicRecordStateMap.RecordMetadata(
                Instant.parse("2026-01-01T00:00:00Z"), AtomicRecordStateMap.RecordAvailability.KEYS_AVAILABLE,
                ORIGIN_SAE, ORIGIN_SAE, "token-1", 32);
        assertEquals(metadata, replyRoundTrip(metadata));
        for (AtomicRecordStateMap.DeleteOutcome outcome : AtomicRecordStateMap.DeleteOutcome.values()) {
            assertSame(outcome, replyRoundTrip(outcome));
        }
        assertEquals("pong", replyRoundTrip("pong"));
        assertInstanceOf(PairLockLostException.class, replyRoundTrip(new PairLockLostException("lost")));
        assertInstanceOf(AccessException.class, replyRoundTrip(new AccessException("no caller")));
        RemoteException wrapped = (RemoteException) replyRoundTrip(
                new RemoteException("insert failed", new IllegalStateException("kme")));
        assertInstanceOf(IllegalStateException.class, wrapped.getCause());
    }

    @Test
    void repliesRejectTypesOutsideTheAllowlist() {
        assertReplyRejected(new HashMap<String, String>());
        assertReplyRejected(new PriorityQueue<String>());
        assertReplyRejected(new java.util.Date());
        assertReplyRejected(SaeFixtures.record(HASH_1, HASH_2, ORIGIN_SAE, List.of("key-1")));
        assertReplyRejected(new javax.management.BadAttributeValueExpException("x"));
        assertReplyRejected(new RemoteException("smuggled", new javax.management.BadAttributeValueExpException("x")));
        List<Object> deep = new ArrayList<>();
        List<Object> cursor = deep;
        for (int i = 0; i < 20; i++) {
            List<Object> next = new ArrayList<>();
            cursor.add(next);
            cursor = next;
        }
        assertReplyRejected(deep);
    }

    @Test
    void replyFilterIsInstalledJvmWide() {
        RmiSerialFilter.installForReplies();
        RmiSerialFilter.installForReplies();
        if (System.getProperty("jdk.serialFilter") == null) {
            assertSame(RmiSerialFilter.REPLIES, ObjectInputFilter.Config.getSerialFilter());
        }
    }

    private static void assertRejected(Object value) {
        assertThrows(InvalidClassException.class, () -> roundTrip(value));
    }

    private static void assertReplyRejected(Object value) {
        assertThrows(InvalidClassException.class, () -> roundTrip(value, RmiSerialFilter.REPLIES));
    }

    private static Object replyRoundTrip(Object value) throws IOException, ClassNotFoundException {
        return roundTrip(value, RmiSerialFilter.REPLIES);
    }

    private static Object roundTrip(Object value) throws IOException, ClassNotFoundException {
        return roundTrip(value, RmiSerialFilter.CALLS);
    }

    private static Object roundTrip(Object value, ObjectInputFilter filter) throws IOException, ClassNotFoundException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            in.setObjectInputFilter(filter);
            return in.readObject();
        }
    }
}
