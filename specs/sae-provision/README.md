# SAE provision model

`SaeProvision.tla` is a plain TLA+ model (no PlusCal) of key-share provisioning
between SAE nodes with pair locks. It covers several SAEs, several concurrent
provision attempts for one client pair, operator deletes and faults: JVM
crashes, stalled holders, aborted operations and lost RMI replies whose handler
still runs later. It is an abstract model of `ProvisionSession`, `PairLocks`,
`PairOperation`, `PairLockRegistry` and `NodeCommands` in
[`JAVA_APPS/modules/sae-node`](../../JAVA_APPS/modules/sae-node/README.md).

## Design modeled

- **Pair lock.** Every SAE keeps one in-memory lock entry per client pair
  (`PairKey` = the sorted pair of client hashes, the same on both SAEs). An
  entry is `[iss, tok, st]`: the issuing SAE, the operation token and
  `"free"`, `"held"` (the holder is alive and renews it every 60 s) or
  `"lapsing"` (nobody renews it; `Expire(n)` may free it at any time). Time is
  abstract: a held lease never expires, a lapsing one may.
- **Token.** `<<edge, k>>`, fresh for every operation (a random 128-bit token
  in Java). Every row written by an operation carries its token.
- **Rows.** `rec[<<sae, device>>]` with `st` `"none"` or `"ka"`
  (`KEYS_AVAILABLE`), the issuer, the counterpart SAE, the token and the key
  material (`kid`, the token of the KME fetch that produced it).
- **Provisioning, one atomic step each:**
  1. `lock1`: lock the SAE with the lower ID (`LockOrder = "lower"`).
  2. `lock2`: lock the SAE with the higher ID. On a refusal the first lock is
     released by token and the attempt ends (`RetryOnRefusal = FALSE`) or
     retries in the same session (`TRUE`).
  3. `check`: read both rows under both locks. If a share exists, the
     operator keeps it or deletes it.
  4. `kme`: get the keys from the KME.
  5. `xfer`: transfer the pads to the origin device.
  6. `pwrite`: the peer writes `KEYS_AVAILABLE(tok)` over RMI, fenced by its
     lock entry (`FencePeerWrite`).
  7. `owrite`: the origin writes `KEYS_AVAILABLE(tok)`, fenced by its lock
     entry.
  8. `complete`: the device gets "share complete".
  9. `relR`, `relL`: release by token, the remote SAE first.
- **Gap guard (`LeaseGuard`).** After a renewal gap (`Stall`) the holder
  renews both entries before its next step. If one of them does not carry the
  token, the operation fails.
- **Operator delete** of a share between `a` (where the operator saw it) and
  `b`. The operator first releases the session locks. The delete then:
  1. locks `min(a,b)`, then `max(a,b)`, with a new token;
  2. deletes `b`'s row over RMI;
  3. deletes `a`'s row only if `b`'s delete succeeded (remote first);
  4. releases both locks and provisions again once.

  Each delete is fenced by the lock and, with `DeleteChecksSeen`, compares the
  row token with the token the operator confirmed (compare-and-delete).
- **One session per SAE.** `Node.usbLoop` serves one device at a time
  (`usb[n]`).

## Faults

| Action | Meaning |
| --- | --- |
| `LostReply(e)` | An RMI reply is lost (remote acquire, peer insert, remote delete, remote release). The caller fails; the handler runs later via `Deliver(m)`, fenced by its token, or is dropped by a crash. A failed remote release makes the entry lapse. |
| `Stall(e)` | The holder stops renewing (GC pause, slow KME or RMI call). Its entries lapse and may expire; the operation continues later. |
| `AbortOp(e)` | KME failure or a failed renewal RMI: the operation aborts and releases. |
| `RenewFails(e)` | A renewal finds an entry without the token (expired and taken, or lost in a crash): the operation fails. |
| `Crash(n)` | JVM crash: all lock entries of `n` are lost, rows survive, the session on `n` ends without "share complete", pending handlers on `n` die, entries the session holds elsewhere lapse. |
| `Expire(n)` | A lapsing entry is freed. |

## Constants

| Constant | Meaning |
| --- | --- |
| `Nodes` | SAE IDs (positive naturals). |
| `Edges` | Provision attempts `<<origin, peer, device>>`, all for one client pair; selected with `Edges <- SingleEdges`, `FanEdges`, `ChainEdges` or `RingEdges`. |
| `MaxSessions` | Sessions (plug-ins and replugs) per attempt. |
| `MaxCrashes`, `MaxStalls`, `MaxAborts`, `MaxLost` | Fault budgets. |
| `OperatorDeletes` | The operator may delete an existing share. |
| `RetryOnRefusal` | A refused lock retries in the same session (`TRUE`) or ends it. |
| `LockOrder` | `"lower"`: lower SAE ID first (design); `"local"`: own SAE first (mutation `mut_a`). |
| `FencePeerWrite` | The peer write requires the lock token (design `TRUE`). |
| `DeleteTakesLocks` | The operator delete takes both locks (design `TRUE`). |
| `DeleteChecksSeen` | Compare-and-delete on the confirmed token (design `TRUE`). |
| `LeaseGuard` | Renew both locks after a renewal gap (design `TRUE`). |

## Configurations

| cfg | `Edges` | Faults and options | Checked |
| --- | --- | --- | --- |
| `SaeProvision.cfg` | `SingleEdges` (1→2) | 3 sessions, 1 crash, 1 stall, 1 abort, 1 lost reply, operator deletes | invariants, `AllSagasFinish`, deadlock |
| `SaeProvision_fan.cfg` | `FanEdges` (1→2, 3→1, 3→2) | 2 sessions, 1 stall, 1 lost reply | invariants, `AllSagasFinish`, deadlock |
| `SaeProvision_chain.cfg` | `ChainEdges` (fan + 4→2, 3→4) | 1 session, 1 lost reply | invariants, `AllSagasFinish`, deadlock |
| `SaeProvision_ring.cfg` | `RingEdges` (1→2, 2→3, 3→4, 4→1) | 2 sessions, 1 crash, retry on refusal | invariants, `AllSagasFinish`, deadlock |
| `SaeProvision_races.cfg` | `FanEdges` | 2 sessions, 1 stall, 1 lost reply, operator deletes | invariants, deadlock |
| `SaeProvision_racesfull.cfg` | `FanEdges` | as `_races` plus 1 crash | invariants, deadlock |

## Invariants and property

| Name | Claim |
| --- | --- |
| `TypeOK` | Types. |
| `MutualExclusion` | Two operations inside the locked region that hold both of their entries never share an SAE. |
| `TerminalSuccessMeansConsistentShare` | At "share complete" both rows are `KEYS_AVAILABLE` with the attempt's token and key material, and the origin device holds those pads. |
| `OriginMarkedAfterPeer` | The origin writes `KEYS_AVAILABLE(tok)` only when the peer row already is `KEYS_AVAILABLE(tok)`. |
| `MatchingSharesWhenCommitted` | Two counterpart rows with the same token hold the same key material. |
| `NoMismatchedDelivery` | What a use-time check (both rows, same token) delivers is the attempt's own pads, held by its origin device, at that attempt's rows. |
| `CompletedShareNotSilentlyLost` | A share reported complete stays intact until an operator delete removes it. |
| `OperatorDeleteOnlyConfirmedShare` | An operator delete removes only the share the operator confirmed. |
| `OperatorDeleteOnlyRowsPresentAtLock` | An operator delete removes only rows present when it held both locks. |
| `RemoteFirstDelete` | A local delete runs only after the remote delete succeeded. |
| `AllSagasFinish` | `<>` every attempt reaches `"done"` (weak fairness on the saga steps, on `Expire` and on `Deliver`). |

Every cfg sets `CHECK_DEADLOCK TRUE`.

## TLC results

TLC 2.19 (rev 5a47802), Java 21, 7 workers on 8 cores, 5461 MB heap:

```bash
java -Xmx6g -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 7 \
     -metadir /tmp/tlc-SaeProvision_ring -config SaeProvision_ring.cfg SaeProvision.tla
```

| cfg | Result | States generated | Distinct states | Depth | Time |
| --- | --- | ---: | ---: | ---: | ---: |
| `SaeProvision` | no error | 103,643 | 38,910 | 40 | 2 s |
| `SaeProvision_fan` | no error | 2,472,791 | 846,298 | 57 | 35 s |
| `SaeProvision_chain` | no error | 1,339,900 | 393,993 | 48 | 25 s |
| `SaeProvision_ring` | no error | 4,320,172 | 1,191,007 | 54 | 1 min 8 s |
| `SaeProvision_races` | no error (safety) | 12,646,725 | 4,602,913 | 98 | 45 s |
| `SaeProvision_racesfull` | no error (safety) | 258,450,361 | 79,448,065 | 107 | 13 min 23 s |

## Mutation checks

Each cfg in [`mutations/`](mutations/) switches off one guard of the design
and must fail. Run them from this directory, e.g.
`-config mutations/mut_b_nofence.cfg SaeProvision.tla`.

| cfg | Guard switched off | Base cfg | TLC result | States generated / distinct | Trace | Time |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `mut_a_localfirst` | lower ID first (`LockOrder = "local"`) | ring | `AllSagasFinish` violated: the four attempts refuse each other forever (lasso back to state 15) | 4,663,491 / 1,268,593 | 30 states | 1 min 4 s |
| `mut_b_nofence` | token check on the peer write (`FencePeerWrite = FALSE`) | single | `OriginMarkedAfterPeer` violated | 11,993 / 5,376 | 19 states | 0 s |
| `mut_d_noseen` | compare-and-delete on the confirmed token (`DeleteChecksSeen = FALSE`) | races | `OperatorDeleteOnlyConfirmedShare` violated | 1,991,361 / 733,664 | 32 states | 7 s |
| `mut_e_noleaseguard` | renew both after a gap (`LeaseGuard = FALSE`) | races | `TerminalSuccessMeansConsistentShare` violated | 471,473 / 157,505 | 22 states | 2 s |

## Open limitations

- A device may hold keys without "share complete": when the commit after the
  device ack fails (lost lock, unreachable peer), the device has the pads but
  the share is not complete; the operator sees a warning and provisions again.
- Locks are in memory. An SAE restart releases all of its locks; operations
  that held one fail at their next renewal or fenced write.
- A refused lock ends the attempt; the operator retries.

## Not modeled

- Key material contents, QKD key IDs and ciphertext; `kid` names the KME
  fetch whose keys a row holds.
- More than one client pair, record retention, the KME and HSM themselves,
  SQLite busy timeouts and the device protocol.
- Real time: a held lease does not expire, a lapsing one may expire at any
  point.

## How to run

Use [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases) 2.19 from this
directory:

```bash
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 7 \
     -metadir /tmp/tlc-sae -config SaeProvision_races.cfg SaeProvision.tla
```

`-metadir` keeps TLC's state files out of this directory.
