# LabSwitch

Lab-only USB owner switch. Writes a shared JSON file. **Production Java never
reads that file.** [scripts/lab-run.py](../../../scripts/lab-run.py) watches it
and restarts the child JVM with a new `USB_SERIAL_PORT`, which frees the serial
port:

- **`userapp-1` / `userapp-2`** — pinned to client-1 / client-2; run only while
  owner is `USER`, each with its own PTY and device cert.
- **`node-1` / `node-2`** — the pane stays. On `USER` / `SAE` the wrapper kills
  SaeNode and starts it again. Owner `SAE` sets `USB_SERIAL_PORT` to that
  client's serial; owner `USER` sets `none`. Operator stdin is the new process.

There is **no CL 1 / CL 2** command — both keychains are live in parallel.
Pane layout does not change.

**Not used in production** — run `scripts/java.sh node env/node-N.env` /
`userapp env/userapp-N.env` on silicon / home PCs (no wrapper, no lab file).

Entry point: `fel.cvut.lab.LabSwitchApp`.

## Commands

| Input | Effect |
| --- | --- |
| `USER` | Both **UserApp** panes own USB (encrypt / decrypt / manage / bring-up). Nodes stay up without USB. |
| `SAE` | Both **SaeNode** panes own USB and arm `PROVISION`. UserApp panes idle. |
| `status` | Print current file |
| `quit` | Exit |

One-shot:

```bash
cd JAVA_APPS
export USB_LAB_FILE=/tmp/otp-keychain-lab.json
mvn -pl :lab-switch -am exec:java -Dexec.args='SAE'
# or: scripts/java.sh lab 'USER'
```

## File

Default path: `/tmp/otp-keychain-lab.json` (override with `USB_LAB_FILE` on the
lab CLI / wrapper only).

```json
{
  "mode" : "USER",
  "nodes" : {
    "client-1" : {
      "serialPort" : "/tmp/ttyACM-se1"
    },
    "client-2" : {
      "serialPort" : "/tmp/ttyACM-se2"
    }
  }
}
```

`mode` is only `USER` or `SAE`. Node map keys are `client-1` / `client-2`
(legacy `client`, `host`, `nativePort`, and `terminalPort` fields in old files
are ignored).

Each `se_host` publishes its own PTY; under a given owner both matching Java
processes open CDC at once (different paths).

Delete this source tree (`src/LabSwitch/`) and drop `scripts/lab-run.py` to remove the helper.
