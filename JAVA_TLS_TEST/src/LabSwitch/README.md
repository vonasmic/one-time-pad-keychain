# LabSwitch

Lab-only cable + client selector. Writes a shared JSON file. **Production Java
never reads it.** [scripts/lab-run.py](../../../scripts/lab-run.py) (the command
inside the existing `terminal` and `userapp` tmux panes) watches the file and
restarts those JVMs with `USB_SERIAL_PORT` / `NODE_HOSTNAME` /
`NODE_NATIVE_PORT` / `NODE_TERMINAL_PORT` rewritten. For UserApp it also sets
`USERAPP_DEVICE_CERT` to `client/` or `client2/` per
selected keychain. Pane layout does not change.

**Not used in production** — run `scripts/java.sh terminal` / `userapp` on silicon
/ home PCs (no wrapper, no lab file).

Entry point: `fel.cvut.lab.LabSwitchApp`.

Owner and client are independent. **USER** and **SAE** are the two applications that
may own USB CDC (never both at once). CL 1 is always SAE 1; CL 2 is always SAE 2.

## Commands

| Input | Effect |
| --- | --- |
| `USER` | **UserApp** may open USB (encrypt / decrypt / manage). Selected client is unchanged. |
| `SAE` | **TerminalBridge** owns USB and relays `PROVISION` to that client's SAE. Selected client is unchanged (CL 1 → SAE 1, CL 2 → SAE 2). |
| `CL 1` / `1` / `SAE 1` | Select keychain + SAE 1 (`/tmp/ttyACM-se1`, node-1). Owner is unchanged. |
| `CL 2` / `2` / `SAE 2` | Select keychain + SAE 2 (`/tmp/ttyACM-se2`, node-2). Owner is unchanged. |
| `status` | Print current file |
| `quit` | Exit |

One-shot:

```bash
cd JAVA_TLS_TEST
export USB_LAB_FILE=/tmp/otp-keychain-lab.json
mvn -pl :lab-switch -am exec:java -Dexec.args='CL 2'
# or: scripts/java.sh lab 'SAE'
```

## File

Default path: `/tmp/otp-keychain-lab.json` (override with `USB_LAB_FILE` on the
lab CLI / wrapper only).

```json
{
  "mode" : "USER",
  "client" : "client-1",
  "nodes" : {
    "client-1" : {
      "host" : "127.0.0.1",
      "nativePort" : 11111,
      "terminalPort" : 11112,
      "serialPort" : "/tmp/ttyACM-se1"
    },
    "client-2" : {
      "host" : "127.0.0.1",
      "nativePort" : 5020,
      "terminalPort" : 11113,
      "serialPort" : "/tmp/ttyACM-se2"
    }
  }
}
```

`mode` is only `USER` or `SAE`. File values `CLIENT1` / `CLIENT2` / `SAE1` / `SAE2` are
accepted as `SAE` plus that client.

Each `se_host` publishes its own PTY; only one Java process opens CDC at a time.

Delete this source tree (`src/LabSwitch/`) and drop `scripts/lab-run.py` to remove the helper.
