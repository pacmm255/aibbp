#!/bin/bash
# Opus 4.6 Maximum-Strength Research Scans
# Targets: bitso.com, nvio.mx, nvio.ar
# Config: Full Opus brain, high budget, no turn limit, max timeout, all features
# Debug: Full verbose logging with timestamps

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/root/.aibbp/logs/opus_research/${TIMESTAMP}"
mkdir -p "$LOG_DIR"

BUDGET=9999.00     # effectively unlimited
MAX_TURNS=0        # unlimited turns
TIMEOUT=0          # no time limit
MAX_RSS=900        # generous memory
STAGGER=15         # seconds between launches

# Base command — strongest configuration
BASE_CMD="python3 -u -m ai_brain.active.react_main \
    --budget $BUDGET \
    --max-turns $MAX_TURNS \
    --timeout $TIMEOUT \
    --force-opus \
    --no-app-gate \
    --max-rss $MAX_RSS \
    --headless \
    --mode public_bounty \
    --report-format json \
    --email-mode imap \
    --imap-host mail.inbox.lt \
    --imap-user hunter255@inbox.lt \
    --imap-password 7J8PbJbSs6 \
    --email-plus-addressing \
    --email-domain inbox.lt"

# Target 1: bitso.com
TARGET1="https://bitso.com"
DOMAIN1="bitso.com"
PROXY_PORT1=8091
OUTPUT1="$LOG_DIR/findings_bitso.json"
LOG1="$LOG_DIR/bitso.log"

echo "=== Opus 4.6 Maximum Research Scan ==="
echo "Started: $(date)"
echo "Budget: \$$BUDGET per target"
echo "Max turns: unlimited"
echo "Timeout: ${TIMEOUT}s (4h)"
echo "Log dir: $LOG_DIR"
echo ""

echo "[$(date +%H:%M:%S)] Launching: bitso.com (port $PROXY_PORT1)"
nohup bash -c "cd /root/aibbp && $BASE_CMD \
    --target '$TARGET1' \
    --allowed-domains $DOMAIN1 www.$DOMAIN1 api.$DOMAIN1 app.$DOMAIN1 \
    --proxy-port $PROXY_PORT1 \
    --output '$OUTPUT1'" > "$LOG1" 2>&1 &
PID1=$!
echo "  PID: $PID1 | Log: $LOG1"

sleep $STAGGER

# Target 2: nvio.mx
TARGET2="https://nvio.mx"
DOMAIN2="nvio.mx"
PROXY_PORT2=8092
OUTPUT2="$LOG_DIR/findings_nvio_mx.json"
LOG2="$LOG_DIR/nvio_mx.log"

echo "[$(date +%H:%M:%S)] Launching: nvio.mx (port $PROXY_PORT2)"
nohup bash -c "cd /root/aibbp && $BASE_CMD \
    --target '$TARGET2' \
    --allowed-domains $DOMAIN2 www.$DOMAIN2 api.$DOMAIN2 app.$DOMAIN2 \
    --proxy-port $PROXY_PORT2 \
    --output '$OUTPUT2'" > "$LOG2" 2>&1 &
PID2=$!
echo "  PID: $PID2 | Log: $LOG2"

sleep $STAGGER

# Target 3: nvio.ar (may redirect to .com.ar — allow both)
TARGET3="https://nvio.ar"
DOMAIN3="nvio.ar"
PROXY_PORT3=8093
OUTPUT3="$LOG_DIR/findings_nvio_ar.json"
LOG3="$LOG_DIR/nvio_ar.log"

echo "[$(date +%H:%M:%S)] Launching: nvio.ar (port $PROXY_PORT3)"
nohup bash -c "cd /root/aibbp && $BASE_CMD \
    --target '$TARGET3' \
    --allowed-domains $DOMAIN3 www.$DOMAIN3 api.$DOMAIN3 app.$DOMAIN3 nvio.com.ar www.nvio.com.ar \
    --proxy-port $PROXY_PORT3 \
    --output '$OUTPUT3'" > "$LOG3" 2>&1 &
PID3=$!
echo "  PID: $PID3 | Log: $LOG3"

echo ""
echo "=== All 3 Agents Launched ==="
echo "PIDs: $PID1 (bitso) | $PID2 (nvio.mx) | $PID3 (nvio.ar)"
echo ""
echo "Monitor commands:"
echo "  tail -f $LOG1        # bitso.com"
echo "  tail -f $LOG2        # nvio.mx"
echo "  tail -f $LOG3        # nvio.ar"
echo "  ps aux | grep react_main | grep -v grep | wc -l   # count running"
echo "  free -h              # memory"
echo ""

# Save PIDs for easy kill
echo "$PID1 bitso.com" > "$LOG_DIR/pids.txt"
echo "$PID2 nvio.mx" >> "$LOG_DIR/pids.txt"
echo "$PID3 nvio.ar" >> "$LOG_DIR/pids.txt"
echo "PIDs saved to: $LOG_DIR/pids.txt"
