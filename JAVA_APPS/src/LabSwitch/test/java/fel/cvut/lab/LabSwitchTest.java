package fel.cvut.lab;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    void ownerToggleKeepsBothClientNodes() {
        Path file = tmp.resolve("owner.json");
        LabSwitch lab = LabSwitch.open(file);
        assertEquals(LabSwitch.MODE_USER, lab.read().mode());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT1,
                lab.read().node(LabSwitch.ID_CLIENT1).serialPort());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT2,
                lab.read().node(LabSwitch.ID_CLIENT2).serialPort());
        assertEquals(11111, lab.read().node(LabSwitch.ID_CLIENT1).nativePort());
        assertEquals(5020, lab.read().node(LabSwitch.ID_CLIENT2).nativePort());

        LabSwitch.State sae = lab.setMode("SAE");
        assertTrue(sae.holdsTerminal());
        assertEquals(LabSwitch.MODE_SAE, sae.mode());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT1,
                sae.node(LabSwitch.ID_CLIENT1).serialPort());
        assertEquals(LabSwitch.DEFAULT_SERIAL_CLIENT2,
                sae.node(LabSwitch.ID_CLIENT2).serialPort());

        LabSwitch.State user = lab.setMode("USER");
        assertTrue(user.holdsUser());
        assertEquals(2, user.nodes().size());

        assertThrows(IllegalArgumentException.class, () -> lab.setMode("CL 2"));
    }
}
