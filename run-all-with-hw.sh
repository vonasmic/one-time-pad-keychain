#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/scripts/run-all.sh" --config "$ROOT/scripts/configs/with-hw" "$@"
