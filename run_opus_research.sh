#!/bin/bash
# Opus 4.6 research run — full verbose logging of every interaction
# Target: taxify.eu (Bolt) — known to have real attack surface
# ALL turns use Opus (--force-opus), full transcript logging

TARGET="https://taxify.eu"
BUDGET=10.00
MAX_TURNS=50
LOG_DIR="/root/.aibbp/opus_research"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/opus_taxify_${TIMESTAMP}.log"
TRANSCRIPT_NOTE="$LOG_DIR/opus_taxify_${TIMESTAMP}_notes.txt"

echo "=== Opus 4.6 Research Run ===" | tee "$TRANSCRIPT_NOTE"
echo "Target: $TARGET" | tee -a "$TRANSCRIPT_NOTE"
echo "Budget: \$$BUDGET" | tee -a "$TRANSCRIPT_NOTE"
echo "Max turns: $MAX_TURNS" | tee -a "$TRANSCRIPT_NOTE"
echo "Log: $LOG_FILE" | tee -a "$TRANSCRIPT_NOTE"
echo "Started: $(date)" | tee -a "$TRANSCRIPT_NOTE"
echo ""

# Run with Claude Opus for ALL turns (--force-opus)
# --no-app-gate to skip app model requirement for faster start
python3 -u -m ai_brain.active.react_main \
    --target "$TARGET" \
    --budget "$BUDGET" \
    --max-turns "$MAX_TURNS" \
    --no-app-gate \
    --force-opus \
    --timeout 7200 \
    2>&1 | tee "$LOG_FILE"

echo ""
echo "Finished: $(date)" | tee -a "$TRANSCRIPT_NOTE"
echo "Log saved: $LOG_FILE"
