#!/usr/bin/env bash
set -euo pipefail

PROXY_DIR="${RUNNER_TEMP:-/tmp}/checkin-proxy"

for PID_FILE in "${PROXY_DIR}/mihomo.pid" "${PROXY_DIR}/xray.pid"; do
	if [[ -f "${PID_FILE}" ]]; then
		echo "[INFO] Stopping proxy (pid $(cat "${PID_FILE}"))"
		kill "$(cat "${PID_FILE}")" 2>/dev/null || true
		rm -f "${PID_FILE}"
	fi
done
