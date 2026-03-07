#!/bin/bash
# Smart agent launcher — calculates max agents based on available RAM
# Usage: ./launch_agents.sh [commands_file] [max_rss_mb]

set -e

COMMANDS_FILE="${1:-$HOME/.aibbp/bugcrowd_scan_commands.txt}"
MAX_RSS_MB="${2:-700}"
LOG_DIR="$HOME/.aibbp/logs/bugcrowd"
STAGGER_DELAY=10  # seconds between agent launches

# Calculate safe agent count
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/ {print $2}')
AVAILABLE_RAM_MB=$(free -m | awk '/^Mem:/ {print $7}')
# Reserve 4GB for system + chrome overhead
RESERVE_MB=4096
USABLE_MB=$((AVAILABLE_RAM_MB - RESERVE_MB))
# Each agent uses ~700MB Python + ~200MB chrome = ~900MB total
AGENT_FOOTPRINT_MB=900
MAX_AGENTS=$((USABLE_MB / AGENT_FOOTPRINT_MB))

if [ "$MAX_AGENTS" -lt 1 ]; then
    MAX_AGENTS=1
fi

TOTAL_COMMANDS=$(wc -l < "$COMMANDS_FILE")

echo "=== Agent Launcher ==="
echo "  Total RAM:      ${TOTAL_RAM_MB}MB"
echo "  Available RAM:  ${AVAILABLE_RAM_MB}MB"
echo "  Reserved:       ${RESERVE_MB}MB"
echo "  Agent footprint: ${AGENT_FOOTPRINT_MB}MB"
echo "  Max safe agents: $MAX_AGENTS"
echo "  Total commands:  $TOTAL_COMMANDS"
echo "  Max RSS/agent:   ${MAX_RSS_MB}MB"
echo "  Stagger delay:   ${STAGGER_DELAY}s"

if [ "$MAX_AGENTS" -lt "$TOTAL_COMMANDS" ]; then
    echo ""
    echo "  WARNING: Only launching $MAX_AGENTS of $TOTAL_COMMANDS agents (RAM limited)"
    echo "  Remaining agents will be skipped. Increase RAM or reduce agents."
fi

echo ""
mkdir -p "$LOG_DIR"

# Clean stale lock files
rm -f "$HOME/.aibbp/agent_locks/"*.lock 2>/dev/null

i=0
while IFS= read -r cmd; do
    i=$((i+1))
    if [ "$i" -gt "$MAX_AGENTS" ]; then
        echo "[$i/$TOTAL_COMMANDS] SKIPPED (RAM limit)"
        continue
    fi

    # Extract target for log filename
    target=$(echo "$cmd" | grep -oP '(?<=--target ")[^"]+' | sed 's|https://||;s|/.*||;s|\.|-|g')
    logfile="$LOG_DIR/${target}.log"

    # Append --max-rss to command
    cmd_with_rss="$cmd --max-rss $MAX_RSS_MB"

    echo "[$i/$TOTAL_COMMANDS] Starting: $target"
    nohup bash -c "cd /root/aibbp && $cmd_with_rss" > "$logfile" 2>&1 &

    if [ "$i" -lt "$MAX_AGENTS" ] && [ "$i" -lt "$TOTAL_COMMANDS" ]; then
        sleep "$STAGGER_DELAY"
    fi
done < "$COMMANDS_FILE"

echo ""
echo "Launched $((i < MAX_AGENTS ? i : MAX_AGENTS)) agents."
echo "Monitor: ps aux | grep react_main | grep -v grep | wc -l"
echo "Memory:  free -h"
echo "Logs:    $LOG_DIR/"
