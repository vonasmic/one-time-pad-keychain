package fel.cvut.node;

import fel.cvut.node.recordManager.AtomicRecordStateMap;
import fel.cvut.node.recordManager.ClientRecord;
import fel.cvut.se.SeKemFill;
import fel.cvut.se.SeSessionUplink;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProvisionSessionTest {

    private static final String LOCAL = "1";
    private static final String PEER = "2";
    private static final byte[] DOWNLINK = {9, 9, 9};

    @Test
    void insertedAndConfirmedGenerates() throws Exception {
        FakeRecords records = new FakeRecords();
        records.insert = AtomicRecordStateMap.SynchronizeOutcome.INSERTED;
        FakeExchange exchange = new FakeExchange(Optional.of(List.of("key")));
        FakeOperator operator = new FakeOperator(true);
        ProvisionSession session = session(records, exchange, operator);

        ProvisionSession.Outcome out = session.process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertEquals(DOWNLINK, ((ProvisionSession.Outcome.Generated) out).payload());
        assertEquals(1, operator.confirms.size());
    }

    @Test
    void insertedAndDeclinedReselects() throws Exception {
        FakeRecords records = new FakeRecords();
        records.insert = AtomicRecordStateMap.SynchronizeOutcome.INSERTED;
        FakeOperator operator = new FakeOperator(false);
        ProvisionSession.Outcome out = session(records, new FakeExchange(Optional.empty()), operator)
                .process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.Reselect.class, out);
        assertEquals(1, records.deletes);
    }

    @Test
    void notInsertedIsInProgress() throws Exception {
        FakeRecords records = new FakeRecords();
        records.insert = AtomicRecordStateMap.SynchronizeOutcome.NOT_INSERTED;
        FakeOperator operator = new FakeOperator(true);
        ProvisionSession.Outcome out = session(records, new FakeExchange(Optional.empty()), operator)
                .process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertEquals(
                "Record sharing is in progress on another SAE. Wait 10 seconds and then retry.",
                ((ProvisionSession.Outcome.InProgress) out).operatorMessage());
        assertEquals(1, operator.notifies.size());
        assertEquals(
                "Record sharing is in progress on another SAE. Wait 10 seconds and then retry.",
                operator.notifies.get(0));
    }

    @Test
    void availableShareDeliversExisting() throws Exception {
        FakeRecords records = new FakeRecords();
        records.insert = AtomicRecordStateMap.SynchronizeOutcome.RECORD_AVAILABLE;
        records.metadata = Optional.of(shareMetadata(PEER));
        records.payloads.put("h1|h2", List.of("key"));
        FakeOperator operator = new FakeOperator(true);
        ProvisionSession.Outcome out = session(records, new FakeExchange(Optional.empty()), operator)
                .process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.Existing.class, out);
        assertEquals(DOWNLINK, ((ProvisionSession.Outcome.Existing) out).payload());
    }

    @Test
    void differentSaeShareUsedWhenConfirmed() throws Exception {
        FakeRecords records = differentSaeRecords();
        FakeOperator operator = new FakeOperator(true);
        ProvisionSession.Outcome out = session(records, new FakeExchange(Optional.empty()), operator)
                .process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.Existing.class, out);
        assertEquals(1, operator.confirms.size());
    }

    @Test
    void differentSaeShareKeptWhenDeleteDeclined() throws Exception {
        FakeRecords records = differentSaeRecords();
        FakeOperator operator = new FakeOperator(false, false);
        ProvisionSession.Outcome out = session(records, new FakeExchange(Optional.empty()), operator)
                .process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.InProgress.class, out);
        assertEquals("Existing keys were kept. No keys were sent to the device.",
                ((ProvisionSession.Outcome.InProgress) out).operatorMessage());
        assertEquals(2, operator.confirms.size());
        assertTrue(operator.confirms.get(1).contains("permanently delete those keys"));
        assertEquals(0, records.deletes);
    }

    @Test
    void differentSaeShareDeletedWhenDeleteConfirmed() throws Exception {
        FakeRecords records = differentSaeRecords();
        FakeOperator operator = new FakeOperator(false, true);
        ProvisionSession.Outcome out = session(records, new FakeExchange(Optional.of(List.of("key"))), operator)
                .process(record(), uplink());
        assertInstanceOf(ProvisionSession.Outcome.Generated.class, out);
        assertEquals(2, operator.confirms.size());
        assertTrue(operator.confirms.get(1).contains("permanently delete those keys"));
        assertEquals(1, records.deletes);
    }

    private static FakeRecords differentSaeRecords() {
        FakeRecords records = new FakeRecords();
        records.insert = AtomicRecordStateMap.SynchronizeOutcome.RECORD_SHARED_WITH_DIFFERENT_SAE;
        records.metadata = Optional.of(shareMetadata("3"));
        records.payloads.put("h1|h2", List.of("key"));
        return records;
    }

    private static AtomicRecordStateMap.RecordMetadata shareMetadata(String saeId) {
        return new AtomicRecordStateMap.RecordMetadata(
                Instant.parse("2026-01-01T00:00:00Z"),
                AtomicRecordStateMap.RecordAvailability.RECORD_AVAILABLE,
                saeId,
                saeId);
    }

    private static ProvisionSession session(
            FakeRecords records, FakeExchange exchange, FakeOperator operator
    ) {
        SeKemFill kem = mock(SeKemFill.class);
        when(kem.buildDownlink(any(), any(), anyByte())).thenReturn(DOWNLINK);
        return new ProvisionSession(LOCAL, records, exchange, operator, (sae, h1, h2) -> {
        }, kem);
    }

    private static ClientRecord record() {
        return new ClientRecord("h1", "h2", List.of(), PEER);
    }

    private static SeSessionUplink uplink() {
        return mock(SeSessionUplink.class);
    }

    private static final class FakeRecords implements ProvisionSession.Records {
        AtomicRecordStateMap.SynchronizeOutcome insert =
                AtomicRecordStateMap.SynchronizeOutcome.INSERTED;
        Optional<AtomicRecordStateMap.RecordMetadata> metadata = Optional.empty();
        final Map<String, List<String>> payloads = new HashMap<>();
        int deletes;

        @Override
        public AtomicRecordStateMap.SynchronizeOutcome synchronize(
                ClientRecord.ClientHeader header, String localSaeId) {
            return insert;
        }

        @Override
        public Optional<AtomicRecordStateMap.RecordMetadata> get(String clientHash1, String clientHash2) {
            return metadata;
        }

        @Override
        public void tryDelete(String clientHash1, String clientHash2, String issuingSaeId, String reason) {
            deletes++;
        }

        @Override
        public void forceDeleteLocal(String clientHash1, String clientHash2, String reason) {
            deletes++;
            insert = AtomicRecordStateMap.SynchronizeOutcome.INSERTED;
        }

        @Override
        public Optional<List<String>> readPayload(String clientHash1, String clientHash2) {
            return Optional.ofNullable(payloads.get(clientHash1 + "|" + clientHash2));
        }

        @Override
        public void removePayload(String clientHash1, String clientHash2) {
            payloads.remove(clientHash1 + "|" + clientHash2);
        }
    }

    private static final class FakeExchange implements ProvisionSession.Exchange {
        private final Optional<List<String>> keys;

        private FakeExchange(Optional<List<String>> keys) {
            this.keys = keys;
        }

        @Override
        public Optional<List<String>> completeNewExchange(ClientRecord clientRecord, SeSessionUplink uplink) {
            return keys;
        }
    }

    private static final class FakeOperator implements ProvisionSession.Operator {
        private final boolean[] answers;
        private int index;
        final List<String> confirms = new ArrayList<>();
        final List<String> notifies = new ArrayList<>();

        private FakeOperator(boolean... answers) {
            this.answers = answers.length == 0 ? new boolean[]{true} : answers;
        }

        @Override
        public boolean confirm(String message) {
            confirms.add(message);
            boolean answer = answers[Math.min(index, answers.length - 1)];
            index++;
            return answer;
        }

        @Override
        public void notify(String message) {
            notifies.add(message);
        }
    }
}
