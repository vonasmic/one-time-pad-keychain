# SAE provision PlusCal

One spec of the current Java: reserve pair → lockFetch → insert → origin
commit → device ack, then a later origin retry or peer-device delivery.

`pcal.trans` already wrote the TLA+ under `BEGIN TRANSLATION`. Re-run it only
if you edit the PlusCal.

## Names


| Spec                                                  | Meaning                                                             |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| `originRecord` / `peerRecord`                         | That SAE's `record_availability` row                                |
| `NoRecord`                                            | No row                                                              |
| `Synchronization`                                     | `RECORD_SYNCHRONIZATION` — pair reserved                            |
| `FetchLocked`                                         | `RECORD_FETCHING_STARTED` — fetch lock held                         |
| `ShareCommitted`                                      | `RECORD_AVAILABLE` — share committed but origin fill did not finish |
| `OriginProvisioned`                                   | `RECORD_PROVISIONED` — origin device acked (origin SAE only)        |
| `originReservationExpired` / `peerReservationExpired` | `date_of_creation` older than 2 minutes                             |
| `originHasShare`                                      | Origin finished commit (no ciphertext file on origin)               |
| `peerHasKeyMaterial`                                  | Peer store holds the ciphertext                                     |
| `originProcessDied`                                   | Origin JVM died mid-saga; no compensating delete                    |
| `twoMinutesElapsed`                                   | Reservation clock advanced once after the saga                      |
| `originSaeReachable`                                  | Later `getRecordMetadata` to the origin succeeds                    |
| `laterAttemptReadOrigin`                              | A later provision attempt consulted the origin                      |
| `originDeviceHasKeys` / `peerDeviceHasKeys`           | That SE acked the downlink                                          |
| `terminalReportedSuccess`                             | Terminal 100% line after a consistent origin share                  |




## How to run

Paste `SaeProvision.tla` and `SaeProvision.cfg` into the
[TLA+ By Example](https://learning.tlapl.us/) playground, or use
[tla2tools.jar](https://github.com/tlaplus/tlaplus/releases)
from this directory:

```bash
java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC -noTE -config SaeProvision.cfg SaeProvision.tla
```

TLC should find no error for the invariants in `SaeProvision.cfg`.

## What the spec claims

Always:

- If both sides hold a committed share, the material flags match.
- The peer row is never `OriginProvisioned`.
- `OriginProvisioned` exists only after the origin device ack.
- The peer device is filled only if the origin device already acked, and
only after both rows were deleted (delete-before-send).
- The terminal success line is reported only after `MarkOriginProvisioned`
returns a consistent share: origin device has keys, origin row is
`OriginProvisioned`, peer row is `ShareCommitted`, and the material flags
match. A later peer delivery may then consume both rows.

After the reservation window **and** an origin read (`laterAttemptReadOrigin`,
origin reachable):

- leftover peer `ShareCommitted` whose origin is not `OriginProvisioned` is gone, or
- the origin is still in a fresh in-progress state.

On origin retry, leftover origin `ShareCommitted` is deleted (peer row too)
and a new `Synchronization` starts with no operator prompt.

## What it does not claim

These are Java behavior. The spec includes them; it does not pretend they
heal:

- Origin unreachable: the later attempt neither deletes nor fills. A
leftover `ShareCommitted` can sit. -> Intended behaviour
- Crash after delete-before-send and before the peer socket write: origin device has keys, both rows gone, peer device empty. -> Unfortunate but required to prevent double share

