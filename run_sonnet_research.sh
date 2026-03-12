#!/bin/bash
# Sonnet 4.5 research run — comparison with Opus run
# Same target, same budget, same flags — only model differs

TARGET="https://taxify.eu"
BUDGET=10.00
MAX_TURNS=50
LOG_DIR="/root/.aibbp/opus_research/opus_vs_sonnet"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/sonnet_taxify_${TIMESTAMP}.log"

echo "=== Sonnet 4.5 Research Run ==="
echo "Target: $TARGET"
echo "Budget: \$$BUDGET"
echo "Max turns: $MAX_TURNS"
echo "Log: $LOG_FILE"
echo "Started: $(date)"
echo ""

# Run with Claude Sonnet for ALL turns (--force-sonnet)
# Same flags as Opus run for fair comparison
python3 -u -m ai_brain.active.react_main \
    --target "$TARGET" \
    --budget "$BUDGET" \
    --max-turns "$MAX_TURNS" \
    --no-app-gate \
    --force-sonnet \
    --timeout 7200 \
    2>&1 | tee "$LOG_FILE"

echo ""
echo "Finished: $(date)"
echo "Log saved: $LOG_FILE"
