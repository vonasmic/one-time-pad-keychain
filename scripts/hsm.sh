#!/usr/bin/env bash
# Check an already-running HSM and run one-time csadm setup if needed.
set -euo pipefail
# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

CSADM="$ROOT/ultimaco/hsm-simulator/Software/Linux/Administration/csadm"
ADMIN_KEY="$ROOT/ultimaco/hsm-simulator/Software/Linux/Administration/key/ADMIN_SIM.key"
QP_FW_LINUX="$ROOT/ultimaco/quantum-protect/linux/firmware/1.5.0.0/sim5_linux"
QP_FW_WIN="$ROOT/ultimaco/quantum-protect/windows/firmware/1.5.0.0/sim5_windows"

[[ -f "$CSADM" && -f "$ADMIN_KEY" ]] || die "missing csadm or ADMIN_SIM.key (see ultimaco/*/README.md)"
chmod +x "$CSADM" 2>/dev/null || true
[[ -f "$JAVA_DIR/env/hsm.env" ]] || die "missing $JAVA_DIR/env/hsm.env"

source_env "$JAVA_DIR/env/hsm.env"
HSM_DEV="${HSM_DEVICE:-3001@127.0.0.1}"
pin="${HSM_PIN:-12345678}"
if [[ "$HSM_DEV" == *@127.0.0.1 || "$HSM_DEV" == *@localhost ]]; then
  fwdir="$QP_FW_LINUX"
  suffix=linux
else
  fwdir="$QP_FW_WIN"
  suffix=win
fi

timeout 5 "$CSADM" Dev="$HSM_DEV" LogonSign="ADMIN,$ADMIN_KEY" GetState >/dev/null \
  || die "HSM not reachable at $HSM_DEV. Start the simulator first (JAVA_APPS/README.md#hsm-setup)."

users="$("$CSADM" Dev="$HSM_DEV" LogonSign="ADMIN,$ADMIN_KEY" ListUsers 2>/dev/null || true)"
fw="$("$CSADM" Dev="$HSM_DEV" LogonSign="ADMIN,$ADMIN_KEY" ListFirmware 2>/dev/null || true)"
if [[ "$users" == *CXI_HMAC* ]] && grep -qi pqmi <<<"$fw"; then
  log "HSM already initialized"
  exit 0
fi

log "HSM csadm setup"
"$CSADM" Dev="$HSM_DEV" LogonSign="ADMIN,$ADMIN_KEY" DeleteUser=CXI_HMAC || true
"$CSADM" Dev="$HSM_DEV" LogonSign="ADMIN,$ADMIN_KEY" \
  'AddUser=CXI_HMAC,00000002{CXI_GROUP=*},hmacpwd,87654321'
"$CSADM" Dev="$HSM_DEV" LogonPass=CXI_HMAC,87654321 "ChangeUser=CXI_HMAC,${pin}"
"$CSADM" Dev="$HSM_DEV" LogonSign="ADMIN,$ADMIN_KEY" \
  "LoadFile=$fwdir/hbs_sim_${suffix}.mtc" \
  "LoadFile=$fwdir/ml_sim_${suffix}.mtc" \
  "LoadFile=$fwdir/pqmi_sim_${suffix}.mtc" \
  Restart
