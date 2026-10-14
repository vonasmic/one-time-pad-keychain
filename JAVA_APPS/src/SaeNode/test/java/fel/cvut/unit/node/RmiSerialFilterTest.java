package fel.cvut.unit.node;

import fel.cvut.harness.SaeFixtures;
import fel.cvut.node.Address;
import fel.cvut.node.interNodeCommunication.RmiSerialFilter;
import fel.cvut.node.recordManager.ClientRecord;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.PriorityQueue;

import static fel.cvut.harness.SaeFixtures.HASH_1;
import static fel.cvut.harness.SaeFixtures.HASH_2;
import static fel.cvut.harness.SaeFixtures.ORIGIN_SAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** F-06: the RMI call filter accepts exactly the NodeCommands argument types. */
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

    private static void assertRejected(Object value) {
        assertThrows(InvalidClassException.class, () -> roundTrip(value));
    }

    private static Object roundTrip(Object value) throws IOException, ClassNotFoundException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            in.setObjectInputFilter(RmiSerialFilter.CALLS);
            return in.readObject();
        }
    }
}
