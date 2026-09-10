# Utimaco Quantum Protect

Place the Utimaco QuantumProtect evaluation SDK here.
The SDK is proprietary (Utimaco license) and is **not committed**.

Unzip so this directory is the SDK root (not an extra nested version folder).

Expected layout:

```
linux/sim5_linux/bin/cs_sim.sh
linux/firmware/1.5.0.0/sim5_linux/hbs_sim_linux.mtc
linux/firmware/1.5.0.0/sim5_linux/ml_sim_linux.mtc
linux/firmware/1.5.0.0/sim5_linux/pqmi_sim_linux.mtc
windows/sim5_windows/bin/cs_sim.bat
windows/firmware/1.5.0.0/sim5_windows/hbs_sim_win.mtc
windows/firmware/1.5.0.0/sim5_windows/ml_sim_win.mtc
windows/firmware/1.5.0.0/sim5_windows/pqmi_sim_win.mtc
```

Java JCE / PQMI sources used by Maven still go in `JAVA_TLS_TEST/vendor/` (also not committed). Copy them from `Crypto_APIs/` in this tree.

See [JAVA_TLS_TEST/README.md](../../JAVA_TLS_TEST/README.md#hsm-setup) for start and `csadm` init. `./run-all.sh` does not start the Windows simulator.
