#!/usr/bin/env bash
set -euo pipefail

SCAN_ID="${1:-1}"
BACKEND_URL="${2:-http://localhost:8080/api/v1/runtime/events}"

echo "=========================================================="
echo "   AutoForge Linux eBPF Kernel Collector"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[WARN] Not running as root. Running in userland telemetry mode..."
  python3 scripts/ebpf_collector.py --backend-url "$BACKEND_URL" --scan-id "$SCAN_ID" --simulate
else
  echo "[INFO] Running as root. Launching BCC kernel probe collector..."
  python3 scripts/ebpf_collector.py --backend-url "$BACKEND_URL" --scan-id "$SCAN_ID"
fi
