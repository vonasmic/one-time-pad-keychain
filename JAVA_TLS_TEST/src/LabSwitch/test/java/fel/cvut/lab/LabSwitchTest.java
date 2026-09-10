package fel.cvut.lab;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(15)
class LabSwitchTest {

    @TempDir
    Path tmp;

    @Test
    void concurrentSameJvmPollsDoNotThrowOverlappingFileLock() throws Exception {
        Path file = tmp.resolve("lab.json");
        LabSwitch a = LabSwitch.open(file);
        LabSwitch b = LabSwitch.open(file);
        assertSame(a, b);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < 8; i++) {
                LabSwitch lab = i % 2 == 0 ? a : b;
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int n = 0; n < 40; n++) {
                        lab.read();
                        if (n % 5 == 0) {
                            lab.setMode(n % 2 == 0 ? LabSwitch.MODE_USER : LabSwitch.MODE_SAE);
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertTrue(a.read().holdsUser() || a.read().holdsTerminal());
        assertEquals(a.read().mode(), b.read().mode());
    }

    @Test
    void clientSelectsKeychainAndSaeWithoutChangingOwner() {
        Path file = tmp.resolve("clients.json");
        LabSwitch lab = LabSwitch.open(file);
        assertEquals(LabSwitch.MODE_USER, lab.read().mode());
        assertEquals(LabSwitch.ID_CLIENT1, lab.read().clientId());
        assertEquals("CL 1", lab.read().clientLabel());
        assertEquals("SAE 1", lab.read().saeId());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT1, lab.read().serialPort());

        LabSwitch.State c2 = lab.setMode("CL 2");
        assertEquals(LabSwitch.MODE_USER, c2.mode());
        assertEquals(LabSwitch.ID_CLIENT2, c2.clientId());
        assertEquals("CL 2", c2.clientLabel());
        assertEquals("SAE 2", c2.saeId());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT2, c2.serialPort());
        assertEquals(5020, c2.node().nativePort());

        LabSwitch.State sae = lab.setMode("SAE");
        assertTrue(sae.holdsTerminal());
        assertEquals(LabSwitch.MODE_SAE, sae.mode());
        assertEquals(LabSwitch.ID_CLIENT2, sae.clientId());
        assertEquals("SAE 2", sae.saeId());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT2, sae.serialPort());

        LabSwitch.State user = lab.setMode("USER");
        assertTrue(user.holdsUser());
        assertEquals(LabSwitch.ID_CLIENT2, user.clientId());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT2, user.serialPort());

        LabSwitch.State c1 = lab.setMode("CL 1");
        assertEquals(LabSwitch.MODE_USER, c1.mode());
        assertEquals(LabSwitch.ID_CLIENT1, c1.clientId());
        assertEquals("CL 1", c1.clientLabel());
        assertEquals("SAE 1", c1.saeId());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT1, c1.serialPort());
        assertEquals(11111, c1.node().nativePort());

        LabSwitch.State sae1 = lab.setMode("SAE");
        assertEquals(LabSwitch.MODE_SAE, sae1.mode());
        assertEquals(LabSwitch.ID_CLIENT1, sae1.clientId());
        assertEquals("SAE 1", sae1.saeId());
    }

    @Test
    void migratesLegacySaeKeysAndSingleSerialField() throws Exception {
        Path file = tmp.resolve("legacy.json");
        Files.writeString(file, """
                {
                  "mode" : "SAE1",
                  "serialPort" : "/tmp/ttyACM0",
                  "nodes" : {
                    "sae-1" : { "host" : "10.0.0.1", "nativePort" : 11111, "terminalPort" : 11112 },
                    "sae-2" : { "host" : "10.0.0.2", "nativePort" : 5020,  "terminalPort" : 11113 }
                  }
                }
                """, StandardCharsets.UTF_8);
        LabSwitch lab = LabSwitch.open(file);
        LabSwitch.State state = lab.read();
        assertEquals(LabSwitch.MODE_SAE, state.mode());
        assertEquals(LabSwitch.ID_CLIENT1, state.clientId());
        assertEquals("SAE 1", state.saeId());
        assertEquals("10.0.0.1", state.node().host());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT1, state.serialPort());
        assertEquals("10.0.0.2", state.nodes().get(LabSwitch.ID_CLIENT2).host());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT2, state.nodes().get(LabSwitch.ID_CLIENT2).serialPort());
    }
}
