# SAE provision PlusCal

One spec of the current Java: reserve pair → lockFetch → insert → both sides
`RECORD_SHARED` → origin device ack → peer then origin `ORIGIN_PROVISIONED`,
then a later origin retry or peer-device delivery.

`pcal.trans` writes the TLA+ under `BEGIN TRANSLATION`. Re-run it if you edit
the PlusCal. TLC on this spec finds no invariant error (840 distinct states).

## Names


| Spec                                                  | Meaning                                                             |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| `originRecord` / `peerRecord`                         | That SAE's `record_availability` row                                |
| `NoRecord`                                            | No row                                                              |
| `Synchronization`                                     | `RECORD_SYNCHRONIZATION` — pair reserved                            |
| `FetchLocked`                                         | `RECORD_FETCHING_STARTED` — fetch lock held                         |
| `RecordShared`                                        | `RECORD_SHARED` — both databases hold keys; origin has not acked. Same meaning on both SAEs. Incomplete. |
| `OriginProvisioned`                                   | `ORIGIN_PROVISIONED` — origin device acked. Written on the peer, then the origin. |
| `originReservationExpired` / `peerReservationExpired` | `date_of_creation` older than 5 minutes. Does not apply to `OriginProvisioned`. |
| `originHasShare`                                      | Origin finished commit (no ciphertext file on origin)               |
| `peerHasKeyMaterial`                                  | Peer store holds the ciphertext. Cleared when the state row is deleted (cascade). |
| `originProcessDied`                                   | Origin JVM died mid-saga; no compensating delete                    |
| `peerProcessDied`                                     | Peer JVM died mid-saga; no compensating delete                      |
| `fiveMinutesElapsed`                                  | Reservation clock advanced once after the saga                      |
| `originSaeReachable`                                  | Later `getRecordMetadata` to the origin succeeds                    |
| `peerSaeReachable`                                    | Later RMI to the peer succeeds                                      |
| `laterAttemptKind`                                    | `"origin"`, `"peer"`, or `"none"` if that visit was skipped         |
| `originDeviceHasKeys` / `peerDeviceHasKeys`           | That SE acked the downlink                                          |
| `terminalReportedSuccess`                             | Terminal 100% line after both rows are `OriginProvisioned`          |


## How to run

Paste `SaeProvision.tla` and `SaeProvision.cfg` into the
[TLA+ By Example](https://learning.tlapl.us/) playground, or use
[tla2tools.jar](https://github.com/tlaplus/tlaplus/releases)
from this directory:

```bash
java -cp tla2tools.jar pcal.trans SaeProvision.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -noTE -config SaeProvision.cfg SaeProvision.tla
```

TLC should find no error for the invariants in `SaeProvision.cfg`.

## What the spec claims

Always:

- If both sides are `RecordShared` or `OriginProvisioned`, the material flags match.
- The origin row is `OriginProvisioned` only when the peer row already is.
- Either row is `OriginProvisioned` only after the origin device ack.
- The peer device is filled only after both rows were `OriginProvisioned`, and only after both rows were deleted (delete-before-send).
- The terminal success line is reported only when both rows are `OriginProvisioned`, the origin device has the keys, and the material flags match. A later peer delivery may then consume both rows.

After the 5-minute window, when the peer is reachable and the later visit is an origin retry:

- the origin does not still hold a stale `RecordShared`. A fresh `RecordShared` is left in place.

After the 5-minute window, when the origin is reachable and the later visit is a peer-device check:

- the peer does not still hold a stale `RecordShared` (that row is reclaimed and its keys dropped).
- if the peer row is still `OriginProvisioned`, the origin is `OriginProvisioned` or a fresh incomplete row. A missing or stale origin share was deleted.

Every saga label may freeze with either the origin or the peer JVM dead before that step commits. A crash between the peer mark and the origin mark leaves the peer `OriginProvisioned` and the origin `RecordShared`.

## What it does not claim

These are Java behavior. The spec includes them; it does not pretend they heal:

- Origin unreachable: the peer visit neither deletes nor fills. A leftover `RecordShared` or `OriginProvisioned` can sit.
- Peer unreachable: an origin retry of a stale share clears the origin row and leaves the peer row.
- A skipped later visit does not reclaim a stale `RecordShared`. The clock alone does not delete it.
- Crash after delete-before-send and before the peer socket write: origin device has keys, both rows gone, peer device empty.
