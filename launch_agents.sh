#!/bin/bash
# Smart agent launcher with wave-based execution
# Launches MAX_AGENTS at once, queues the rest. When an agent finishes, next one starts.
# Usage: ./launch_agents.sh [commands_file] [max_rss_mb]

set -e

COMMANDS_FILE="${1:-$HOME/.aibbp/bugcrowd_scan_commands.txt}"
MAX_RSS_MB="${2:-700}"
LOG_DIR="$HOME/.aibbp/logs/bugcrowd"
STAGGER_DELAY=10  # seconds between agent launches
POLL_INTERVAL=60  # seconds between checking for finished agents

# Calculate safe agent count
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/ {print $2}')
AVAILABLE_RAM_MB=$(free -m | awk '/^Mem:/ {print $7}')
RESERVE_MB=6144
USABLE_MB=$((AVAILABLE_RAM_MB - RESERVE_MB))
AGENT_FOOTPRINT_MB=650  # Real observed: ~580-630MB per agent
MAX_AGENTS=$((USABLE_MB / AGENT_FOOTPRINT_MB))
HARD_CAP=8  # Never exceed this regardless of RAM (Claude API: 50 RPM limit)

if [ "$MAX_AGENTS" -gt "$HARD_CAP" ]; then
    MAX_AGENTS=$HARD_CAP
fi
if [ "$MAX_AGENTS" -lt 1 ]; then
    MAX_AGENTS=1
fi

TOTAL_COMMANDS=$(wc -l < "$COMMANDS_FILE")

echo "=== Agent Launcher (Wave Mode) ==="
echo "  Total RAM:      ${TOTAL_RAM_MB}MB"
echo "  Available RAM:  ${AVAILABLE_RAM_MB}MB"
echo "  Reserved:       ${RESERVE_MB}MB"
echo "  Agent footprint: ${AGENT_FOOTPRINT_MB}MB"
echo "  Max concurrent:  $MAX_AGENTS"
echo "  Total commands:  $TOTAL_COMMANDS"
echo "  Max RSS/agent:   ${MAX_RSS_MB}MB"
echo "  Stagger delay:   ${STAGGER_DELAY}s"
echo "  Poll interval:   ${POLL_INTERVAL}s"
echo ""

mkdir -p "$LOG_DIR"
rm -f "$HOME/.aibbp/agent_locks/"*.lock 2>/dev/null

# Read all commands into array
mapfile -t COMMANDS < "$COMMANDS_FILE"

# Track PIDs and their targets
declare -A PID_TARGET
NEXT_CMD=0
LAUNCHED=0

launch_agent() {
    local idx=$1
    local cmd="${COMMANDS[$idx]}"
    local target=$(echo "$cmd" | grep -oP '(?<=--target ")[^"]+' | sed 's|https://||;s|/.*||;s|\.|-|g')
    local logfile="$LOG_DIR/${target}.log"
    local cmd_with_rss="$cmd --max-rss $MAX_RSS_MB"

    echo "[$(date +%H:%M:%S)] Starting ($((idx+1))/$TOTAL_COMMANDS): $target"
    nohup bash -c "cd /root/aibbp && $cmd_with_rss" > "$logfile" 2>&1 &
    local pid=$!
    PID_TARGET[$pid]="$target"
    LAUNCHED=$((LAUNCHED+1))
}

# Launch initial wave
while [ "$NEXT_CMD" -lt "$TOTAL_COMMANDS" ] && [ "$NEXT_CMD" -lt "$MAX_AGENTS" ]; do
    launch_agent "$NEXT_CMD"
    NEXT_CMD=$((NEXT_CMD+1))
    if [ "$NEXT_CMD" -lt "$MAX_AGENTS" ] && [ "$NEXT_CMD" -lt "$TOTAL_COMMANDS" ]; then
        sleep "$STAGGER_DELAY"
    fi
done

echo ""
echo "Wave 1: Launched $LAUNCHED agents. $((TOTAL_COMMANDS - NEXT_CMD)) queued."
echo ""

# If all commands launched, no need to wait
if [ "$NEXT_CMD" -ge "$TOTAL_COMMANDS" ]; then
    echo "All $TOTAL_COMMANDS agents launched."
    echo "Monitor: ps aux | grep react_main | grep -v grep | wc -l"
    echo "Memory:  free -h"
    echo "Logs:    $LOG_DIR/"
    exit 0
fi

# Wave mode: poll for finished agents and launch replacements
echo "Entering wave mode — polling every ${POLL_INTERVAL}s for finished agents..."
while [ "$NEXT_CMD" -lt "$TOTAL_COMMANDS" ]; do
    sleep "$POLL_INTERVAL"

    # Check which PIDs are still running
    for pid in "${!PID_TARGET[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            target="${PID_TARGET[$pid]}"
            echo "[$(date +%H:%M:%S)] Finished: $target (PID $pid)"
            unset PID_TARGET[$pid]

            # Launch next queued agent only if enough memory
            if [ "$NEXT_CMD" -lt "$TOTAL_COMMANDS" ]; then
                AVAIL_NOW=$(free -m | awk '/^Mem:/ {print $7}')
                if [ "$AVAIL_NOW" -gt "$((AGENT_FOOTPRINT_MB + RESERVE_MB / 2))" ]; then
                    launch_agent "$NEXT_CMD"
                    NEXT_CMD=$((NEXT_CMD+1))
                    sleep "$STAGGER_DELAY"
                else
                    echo "[$(date +%H:%M:%S)] Skipping launch — only ${AVAIL_NOW}MB available (need $((AGENT_FOOTPRINT_MB + RESERVE_MB / 2))MB)"
                fi
            fi
        fi
    done

    running=${#PID_TARGET[@]}
    remaining=$((TOTAL_COMMANDS - NEXT_CMD))
    echo "[$(date +%H:%M:%S)] Running: $running | Queued: $remaining | Launched: $LAUNCHED/$TOTAL_COMMANDS"
done

echo ""
echo "All $TOTAL_COMMANDS agents launched. Waiting for remaining ${#PID_TARGET[@]} to finish..."
echo "Monitor: ps aux | grep react_main | grep -v grep | wc -l"
echo "Logs:    $LOG_DIR/"
