# LabSwitch

Lab-only USB owner switch. Writes a shared JSON file. **Production Java never
reads it.** [scripts/lab-run.py](../../../scripts/lab-run.py) watches the file
inside the tmux panes:

- **`userapp-1` / `userapp-2`** — pinned to client-1 / client-2; run only while
  owner is `USER`, each with its own PTY and device cert.
- **`terminal-1` / `terminal-2`** — pinned to SAE 1 / SAE 2; always keep the
  operator gateway. USB opens on both PTYs while owner is `SAE`.

There is **no CL 1 / CL 2** command — both keychains are live in parallel.
Pane layout does not change.

**Not used in production** — run `scripts/java.sh terminal env/terminal-N.env` /
`userapp env/userapp-N.env` on silicon / home PCs (no wrapper, no lab file).

Entry point: `fel.cvut.lab.LabSwitchApp`.

## Commands

| Input | Effect |
| --- | --- |
| `USER` | Both **UserApp** panes own USB (encrypt / decrypt / manage / bring-up). Terminals stay up without USB. |
| `SAE` | Both **TerminalBridge** panes own USB and relay `PROVISION`. UserApp panes idle. |
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

`mode` is only `USER` or `SAE`. Node map keys are `client-1` / `client-2`
(legacy `client` field in old files is ignored).

Each `se_host` publishes its own PTY; under a given owner both matching Java
processes open CDC at once (different paths).

Delete this source tree (`src/LabSwitch/`) and drop `scripts/lab-run.py` to remove the helper.
