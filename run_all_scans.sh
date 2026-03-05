#!/bin/bash
# Run ALL bug bounty scans indefinitely with proxy pool + auto-restart
# Z.ai = $0 brain cost, proxy pool bypasses rate limits
# --max-turns 0 = run forever until Ctrl-C
# --budget 9999 = effectively unlimited (Z.ai is free)

TARGETS=(
    "https://capital.com"
    "https://crypto.com"
    "https://linktr.ee"
    "https://hackerone.com"
    "https://merchant.crypto.com"
    "https://pay.crypto.com"
    "https://robinhood.com"
    "https://vault.chiatest.net"
    "https://testnet.bitmex.com"
    "https://app.ens.domains"
)

LOGDIR="/root/aibbp/scan_logs"
mkdir -p "$LOGDIR"

echo "============================================================"
echo "  AIBBP — Launching ${#TARGETS[@]} parallel scans"
echo "  Mode: indefinite (--max-turns 0)"
echo "  Brain: Z.ai GLM-5 (free)"
echo "  Proxy: enabled (--proxy-ratelimit 3)"
echo "  Auto-restart: yes (every 60s check)"
echo "  Logs: $LOGDIR/"
echo "============================================================"

# Declare associative array for PIDs
declare -A PIDS

start_scan() {
    local target="$1"
    local domain=$(echo "$target" | sed 's|https://||' | sed 's|/||g')
    local logfile="$LOGDIR/${domain}.log"

    python -m ai_brain.active.react_main \
        --target "$target" \
        --zai --enable-proxylist --proxy-ratelimit 3 \
        --min-proxies 8 --max-proxies 2000 \
        --budget 9999 --max-turns 0 \
        >> "$logfile" 2>&1 &

    PIDS["$target"]=$!
    echo "[$(date +%H:%M:%S)] Started $domain (PID: ${PIDS[$target]})"
}

# Initial launch with stagger
for t in "${TARGETS[@]}"; do
    start_scan "$t"
    sleep 10
done

echo ""
echo "[*] All ${#TARGETS[@]} scans launched."
echo "[*] Watchdog checking every 60s for crashed processes."
echo "[*] Stop all: kill $$"
echo ""

# Save master PID
echo "$$" > "$LOGDIR/master_pid.txt"

# Watchdog loop: restart crashed processes
while true; do
    sleep 60
    for t in "${TARGETS[@]}"; do
        pid=${PIDS["$t"]}
        if ! kill -0 "$pid" 2>/dev/null; then
            domain=$(echo "$t" | sed 's|https://||' | sed 's|/||g')
            echo "[$(date +%H:%M:%S)] WATCHDOG: $domain died, restarting..."
            start_scan "$t"
            sleep 5
        fi
    done
done
