#!/usr/bin/env bash
set -euo pipefail

PROXY_DIR="${RUNNER_TEMP:-/tmp}/checkin-proxy"
PID_FILE="${PROXY_DIR}/xray.pid"

if [[ -f "${PID_FILE}" ]]; then
	echo "[INFO] Stopping xray proxy (pid $(cat "${PID_FILE}"))"
	kill "$(cat "${PID_FILE}")" 2>/dev/null || true
	rm -f "${PID_FILE}"
else
	echo "[INFO] No xray PID file found at ${PID_FILE}, nothing to stop"
fi
