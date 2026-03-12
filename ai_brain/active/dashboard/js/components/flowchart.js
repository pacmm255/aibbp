/**
 * Mermaid.js-powered flowchart renderer for scan transcripts.
 * Renders transcript events as a detailed top-down flow diagram with
 * subgraphs per turn, color-coded severity, and click-to-inspect popups.
 */
class FlowchartRenderer {
    constructor(container) {
        this.container = container;
        this.events = [];
        this._popup = null;
        this._nodeDataMap = {};  // nodeId -> event data for click handlers
        this._mermaidReady = false;
        this._renderQueued = false;
        this._COLLAPSE_THRESHOLD = 50;  // collapse older turns when > 50 turns

        this._initMermaid();
    }

    _initMermaid() {
        if (typeof mermaid !== 'undefined') {
            this._configureMermaid();
            return;
        }
        // Poll until mermaid CDN has loaded
        const check = setInterval(() => {
            if (typeof mermaid !== 'undefined') {
                clearInterval(check);
                this._configureMermaid();
            }
        }, 100);
    }

    _configureMermaid() {
        try {
            mermaid.initialize({
                startOnLoad: false,
                theme: 'dark',
                themeVariables: {
                    primaryColor: '#1a2130',
                    primaryTextColor: '#c9d1d9',
                    primaryBorderColor: '#3b82f6',
                    lineColor: '#1e2d3d',
                    secondaryColor: '#111820',
                    tertiaryColor: '#0a0e14'
                },
                flowchart: { curve: 'basis', padding: 10 },
                securityLevel: 'loose',  // needed for click callbacks
            });
            this._mermaidReady = true;
            console.log('[flowchart] Mermaid initialized');
            if (this._renderQueued) {
                this._renderQueued = false;
                this._render();
            }
        } catch (err) {
            console.error('Mermaid init failed:', err);
            this.container.innerHTML = '<div style="padding:16px;color:var(--text-muted);">Flowchart unavailable (Mermaid init failed)</div>';
        }
    }

    setEvents(events) {
        this.events = (events || []).map(e => this._normalizeEvent(e));
        this._render();
    }

    addEvent(event) {
        this.events.push(this._normalizeEvent(event));
        this._render();
    }

    /**
     * Normalize events to a consistent format.
     *
     * Transcript JSONL:  {ts, turn, event: "brain_response", data: {content_blocks: [...]}}
     * WS live events:    {event: "brain", turn: 1, tools_called: [...]}
     *
     * Normalizes WS flat events into the transcript nested {turn, event, data} shape.
     */
    _normalizeEvent(e) {
        // Already in transcript format (has nested data object with known fields)
        if (e.data && typeof e.data === 'object' &&
            (e.event === 'brain_response' || e.event === 'tool_call' || e.event === 'tool_result' ||
             e.event === 'compression' || e.event === 'error' || e.event === 'finding' ||
             e.event === 'memory_save' || e.event === 'state_update' || e.event === 'session_start' ||
             e.event === 'session_end' || e.event === 'hypothesis' || e.event === 'chain_discovery' ||
             e.event === 'strategy_reset')) {
            return e;
        }

        // WS flat format — convert to transcript shape
        const turn = e.turn || 0;

        if (e.event === 'brain' || e.event === 'brain_start') {
            return {
                turn,
                event: 'brain_response',
                data: {
                    content_blocks: e.thinking ? [{ type: 'thinking', text: e.thinking }] : [],
                    tool_calls: e.tools_called || [],
                    stop_reason: '',
                },
            };
        }

        if (e.event === 'tool') {
            // WS tool event has both call and result info combined
            return {
                turn,
                event: 'tool_result',
                data: {
                    tool_name: e.tool || 'unknown',
                    result: '',
                    elapsed_ms: e.elapsed_ms || 0,
                    is_error: e.status === 'error',
                },
            };
        }

        if (e.event === 'compress') {
            return {
                turn,
                event: 'compression',
                data: {
                    tier: e.tier || '?',
                    before_chars: e.before_chars || 0,
                    after_chars: e.after_chars || 0,
                    messages_before: e.messages_before || 0,
                    messages_after: e.messages_after || 0,
                },
            };
        }

        if (e.event === 'finding') {
            return {
                turn,
                event: 'finding',
                data: {
                    vuln_type: e.vuln_type || 'finding',
                    severity: e.severity || 'info',
                    endpoint: e.endpoint || '',
                    confirmed: e.confirmed || false,
                    evidence: e.evidence || '',
                    finding_id: e.finding_id || '',
                },
            };
        }

        // Passthrough anything else as-is
        return { turn, event: e.event || 'unknown', data: e.data || e };
    }

    // ── Build the Mermaid definition ────────────────────────────────

    _buildMermaidDef() {
        const lines = ['flowchart TD'];
        const styles = [];
        this._nodeDataMap = {};

        const turns = this._groupByTurn(this.events);
        const turnNumbers = Object.keys(turns).map(Number).sort((a, b) => a - b);

        if (turnNumbers.length === 0) {
            lines.push('    EMPTY["No events yet"]');
            styles.push('style EMPTY fill:#111820,stroke:#3b82f6,color:#c9d1d9');
            return { def: lines.join('\n') + '\n' + styles.join('\n'), nodeCount: 1 };
        }

        // Start node
        lines.push('    START(("Start"))');
        styles.push('style START fill:#0f2a1a,stroke:#22c55e,color:#22c55e');

        let lastNodeId = 'START';
        let nodeCount = 1;
        let collapsedRange = null;

        // Determine which turns to collapse for large transcripts
        const shouldCollapse = turnNumbers.length > this._COLLAPSE_THRESHOLD;
        const collapseEnd = shouldCollapse ? turnNumbers.length - 30 : 0;  // keep last 30 turns expanded

        for (let idx = 0; idx < turnNumbers.length; idx++) {
            const turnNum = turnNumbers[idx];
            const turnEvents = turns[turnNum];

            // Collapse older turns into summary nodes
            if (shouldCollapse && idx < collapseEnd) {
                if (!collapsedRange) {
                    collapsedRange = { start: turnNum, end: turnNum, eventCount: 0, findings: 0, errors: 0, tools: new Set() };
                }
                collapsedRange.end = turnNum;
                collapsedRange.eventCount += turnEvents.length;
                for (const e of turnEvents) {
                    if (e.event === 'finding') collapsedRange.findings++;
                    if (e.event === 'error') collapsedRange.errors++;
                    if (e.event === 'tool_call' || e.event === 'tool_result') {
                        collapsedRange.tools.add((e.data && e.data.tool_name) || '?');
                    }
                }

                // Emit a summary node every 10 collapsed turns or at the end of the collapsed zone
                const isEndOfCollapse = (idx === collapseEnd - 1);
                const isBatch = (collapsedRange.eventCount > 40);
                if (isEndOfCollapse || isBatch) {
                    const cId = `COLLAPSED_${collapsedRange.start}_${collapsedRange.end}`;
                    const toolCount = collapsedRange.tools.size;
                    const label = this._esc(`Turns ${collapsedRange.start}-${collapsedRange.end} | ${collapsedRange.eventCount} events | ${toolCount} tools | ${collapsedRange.findings} findings`);
                    lines.push(`    ${cId}["${label}"]`);
                    styles.push(`style ${cId} fill:#111820,stroke:#6b7280,color:#9ca3af,stroke-dasharray:5 5`);
                    lines.push(`    ${lastNodeId} --> ${cId}`);
                    this._nodeDataMap[cId] = {
                        type: 'collapsed',
                        label: `Turns ${collapsedRange.start}-${collapsedRange.end}`,
                        eventCount: collapsedRange.eventCount,
                        findings: collapsedRange.findings,
                        errors: collapsedRange.errors,
                        tools: [...collapsedRange.tools],
                    };
                    lastNodeId = cId;
                    nodeCount++;
                    collapsedRange = null;
                }
                continue;
            }

            // ── Full turn rendering ──

            const brainEvents = turnEvents.filter(e => e.event === 'brain_response');
            const toolCalls = turnEvents.filter(e => e.event === 'tool_call');
            const toolResults = turnEvents.filter(e => e.event === 'tool_result');
            const compressions = turnEvents.filter(e => e.event === 'compression');
            // Skip standalone error nodes — they duplicate tool_result is_error info
            const findings = turnEvents.filter(e => e.event === 'finding');
            const memorySaves = turnEvents.filter(e => e.event === 'memory_save');
            const hypotheses = turnEvents.filter(e => e.event === 'hypothesis');
            const chains = turnEvents.filter(e => e.event === 'chain_discovery');
            const strategyResets = turnEvents.filter(e => e.event === 'strategy_reset');

            const hasContent = brainEvents.length || toolCalls.length || toolResults.length ||
                compressions.length || findings.length || memorySaves.length;

            if (!hasContent && !hypotheses.length && !chains.length && !strategyResets.length) continue;

            // Open subgraph for this turn
            const sgId = `Turn_${turnNum}`;
            lines.push(`    subgraph ${sgId}["Turn ${turnNum}"]`);

            // ── Brain node ──
            let brainId = null;
            if (brainEvents.length) {
                const brainData = brainEvents[0].data || {};
                const blocks = brainData.content_blocks || [];

                const thinkingBlock = blocks.find(b => b.type === 'thinking');
                const textBlock = blocks.find(b => b.type === 'text');
                let excerpt = '';
                if (thinkingBlock && thinkingBlock.text) {
                    excerpt = thinkingBlock.text.substring(0, 50).replace(/\n/g, ' ');
                } else if (textBlock && textBlock.text) {
                    excerpt = textBlock.text.substring(0, 50).replace(/\n/g, ' ');
                }

                brainId = `brain_${turnNum}`;
                const label = this._esc(`Turn ${turnNum}: ${excerpt}`);
                lines.push(`        ${brainId}("${label}")`);
                styles.push(`style ${brainId} fill:#111d2e,stroke:#3b82f6,color:#93c5fd`);
                lines.push(`    ${lastNodeId} --> ${brainId}`);
                this._nodeDataMap[brainId] = {
                    type: 'brain',
                    turn: turnNum,
                    thinking: thinkingBlock ? thinkingBlock.text : '',
                    text: textBlock ? textBlock.text : '',
                    toolCalls: brainData.tool_calls || [],
                    stopReason: brainData.stop_reason || '',
                    allBlocks: blocks,
                };
                lastNodeId = brainId;
                nodeCount++;
            }

            // ── Tool call + result pairs ──
            const toolPairs = this._pairTools(toolCalls, toolResults);
            const toolNodeIds = [];  // track all tool nodes in this turn for merging

            if (toolPairs.length > 1 && brainId) {
                // MULTIPLE TOOLS: fan-out from brain, then merge
                for (const pair of toolPairs) {
                    const { call, result } = pair;
                    const toolName = (call && call.data && call.data.tool_name) ||
                        (result && result.data && result.data.tool_name) || 'unknown';
                    const elapsed = result && result.data ? result.data.elapsed_ms : null;
                    const isError = result && result.data ? result.data.is_error : false;

                    const toolId = `tool_${turnNum}_${this._sanitizeId(toolName)}_${nodeCount}`;
                    const elapsedStr = elapsed != null ? ` ${this._formatMs(elapsed)}` : '';
                    const statusIcon = isError ? ' X' : ' ok';
                    const label = this._esc(`${toolName}${elapsedStr}${statusIcon}`);

                    lines.push(`        ${toolId}["${label}"]`);
                    styles.push(`style ${toolId} fill:${isError ? '#2a1215' : '#0d1f1d'},stroke:${isError ? '#ef4444' : '#14b8a6'},color:${isError ? '#f87171' : '#5eead4'}`);
                    // Each tool branches from brain
                    lines.push(`    ${brainId} --> ${toolId}`);
                    this._nodeDataMap[toolId] = {
                        type: 'tool', turn: turnNum, toolName,
                        input: call && call.data ? call.data.input : '',
                        toolId: call && call.data ? call.data.tool_id : '',
                        result: result && result.data ? result.data.result : '',
                        elapsed, isError,
                    };
                    toolNodeIds.push(toolId);
                    nodeCount++;
                }

                // Add a merge/join node so flow continues as one line
                const mergeId = `merge_${turnNum}`;
                lines.push(`        ${mergeId}((" "))`);
                styles.push(`style ${mergeId} fill:#111820,stroke:#1e2d3d,color:#1e2d3d`);
                for (const tid of toolNodeIds) {
                    lines.push(`    ${tid} --> ${mergeId}`);
                }
                lastNodeId = mergeId;
                nodeCount++;

            } else if (toolPairs.length === 1) {
                // SINGLE TOOL: just chain linearly
                const { call, result } = toolPairs[0];
                const toolName = (call && call.data && call.data.tool_name) ||
                    (result && result.data && result.data.tool_name) || 'unknown';
                const elapsed = result && result.data ? result.data.elapsed_ms : null;
                const isError = result && result.data ? result.data.is_error : false;

                const toolId = `tool_${turnNum}_${this._sanitizeId(toolName)}_${nodeCount}`;
                const elapsedStr = elapsed != null ? ` ${this._formatMs(elapsed)}` : '';
                const statusIcon = isError ? ' X' : ' ok';
                const label = this._esc(`${toolName}${elapsedStr}${statusIcon}`);

                lines.push(`        ${toolId}["${label}"]`);
                styles.push(`style ${toolId} fill:${isError ? '#2a1215' : '#0d1f1d'},stroke:${isError ? '#ef4444' : '#14b8a6'},color:${isError ? '#f87171' : '#5eead4'}`);
                lines.push(`    ${lastNodeId} --> ${toolId}`);
                this._nodeDataMap[toolId] = {
                    type: 'tool', turn: turnNum, toolName,
                    input: call && call.data ? call.data.input : '',
                    toolId: call && call.data ? call.data.tool_id : '',
                    result: result && result.data ? result.data.result : '',
                    elapsed, isError,
                };
                toolNodeIds.push(toolId);
                lastNodeId = toolId;
                nodeCount++;
            }

            // ── Finding nodes (diamond) — branch off to the side ──
            for (const f of findings) {
                const fd = f.data || {};
                const severity = (fd.severity || 'info').toLowerCase();
                const vulnType = fd.vuln_type || 'finding';
                const confirmed = fd.confirmed ? ' CONFIRMED' : '';

                const fId = `finding_${turnNum}_${nodeCount}`;
                const label = this._esc(`${vulnType}${confirmed}`);
                lines.push(`        ${fId}{{"${label}"}}`);

                const sevStyle = this._severityStyle(severity);
                styles.push(`style ${fId} fill:${sevStyle.fill},stroke:${sevStyle.stroke},color:${sevStyle.color}`);

                // Connect finding to last tool in this turn (or brain if no tools)
                const parentId = toolNodeIds.length ? toolNodeIds[toolNodeIds.length - 1] : lastNodeId;
                lines.push(`    ${parentId} -.- ${fId}`);
                this._nodeDataMap[fId] = {
                    type: 'finding', turn: turnNum, vulnType, severity,
                    endpoint: fd.endpoint || '',
                    confirmed: fd.confirmed || false,
                    evidence: fd.evidence || '',
                    findingId: fd.finding_id || '',
                };
                // Don't update lastNodeId — findings are side branches
                nodeCount++;
            }

            // ── Compression nodes ──
            for (const c of compressions) {
                const cd = c.data || {};
                const tier = cd.tier || '?';
                const before = this._formatSize(cd.before_chars);
                const after = this._formatSize(cd.after_chars);

                const cId = `compress_${turnNum}_${nodeCount}`;
                const label = this._esc(`Compress tier ${tier}: ${before} -> ${after}`);
                lines.push(`        ${cId}["${label}"]`);
                styles.push(`style ${cId} fill:#151718,stroke:#6b7280,color:#9ca3af,stroke-dasharray:3 3`);

                lines.push(`    ${lastNodeId} --> ${cId}`);
                this._nodeDataMap[cId] = {
                    type: 'compression', turn: turnNum, tier,
                    beforeChars: cd.before_chars, afterChars: cd.after_chars,
                    messagesBefore: cd.messages_before, messagesAfter: cd.messages_after,
                };
                lastNodeId = cId;
                nodeCount++;
            }

            // ── Memory save — small side branch, not in main flow ──
            if (memorySaves.length) {
                const mId = `memory_${turnNum}_${nodeCount}`;
                lines.push(`        ${mId}(["Memory saved"])`);
                styles.push(`style ${mId} fill:#1a1128,stroke:#a855f7,color:#c084fc`);
                lines.push(`    ${lastNodeId} -.- ${mId}`);
                this._nodeDataMap[mId] = {
                    type: 'memory_save', turn: turnNum,
                    memoryPath: (memorySaves[0].data || {}).memory_path || '',
                };
                // Don't update lastNodeId — side branch
                nodeCount++;
            }

            // ── Hypothesis nodes — side branches ──
            for (const h of hypotheses) {
                const hd = h.data || {};
                const hId = `hypo_${turnNum}_${nodeCount}`;
                const label = this._esc((hd.hypothesis || '').substring(0, 50));
                lines.push(`        ${hId}(["${label}"])`);
                styles.push(`style ${hId} fill:#231e0d,stroke:#eab308,color:#fde047`);
                lines.push(`    ${lastNodeId} -.- ${hId}`);
                this._nodeDataMap[hId] = {
                    type: 'hypothesis', turn: turnNum,
                    hypothesis: hd.hypothesis || '',
                    priority: hd.priority || 'medium',
                    suggestedTool: hd.suggested_tool || '',
                };
                nodeCount++;
            }

            // ── Chain discovery nodes — side branches ──
            for (const ch of chains) {
                const chd = ch.data || {};
                const chId = `chain_${turnNum}_${nodeCount}`;
                const label = this._esc(chd.chain_name || 'Chain');
                lines.push(`        ${chId}{{"${label}"}}`);
                const sevStyle = this._severityStyle((chd.combined_severity || 'info').toLowerCase());
                styles.push(`style ${chId} fill:${sevStyle.fill},stroke:${sevStyle.stroke},color:${sevStyle.color}`);
                lines.push(`    ${lastNodeId} -.- ${chId}`);
                this._nodeDataMap[chId] = {
                    type: 'chain', turn: turnNum,
                    chainName: chd.chain_name || '',
                    severity: chd.combined_severity || '',
                    description: chd.description || '',
                };
                nodeCount++;
            }

            // ── Strategy reset — in main flow ──
            for (const sr of strategyResets) {
                const srd = sr.data || {};
                const srId = `strat_${turnNum}_${nodeCount}`;
                lines.push(`        ${srId}["${this._esc('Strategy Reset')}"]`);
                styles.push(`style ${srId} fill:#251a0f,stroke:#f97316,color:#fdba74`);
                lines.push(`    ${lastNodeId} --> ${srId}`);
                this._nodeDataMap[srId] = {
                    type: 'strategy_reset', turn: turnNum,
                    reason: srd.reason || '',
                };
                lastNodeId = srId;
                nodeCount++;
            }

            // Close subgraph
            lines.push('    end');
            styles.push(`style ${sgId} fill:#0a0e14,stroke:#1e2d3d,color:#6b7280`);
        }

        // ── End node ──
        lines.push('    ENDNODE(("End"))');
        styles.push('style ENDNODE fill:#2a1215,stroke:#ef4444,color:#ef4444');
        lines.push(`    ${lastNodeId} --> ENDNODE`);
        nodeCount++;

        // ── Click callbacks ──
        for (const nodeId of Object.keys(this._nodeDataMap)) {
            lines.push(`    click ${nodeId} flowchartClickHandler`);
        }

        return { def: lines.join('\n') + '\n' + styles.join('\n'), nodeCount };
    }

    // ── Render ──────────────────────────────────────────────────────

    async _render() {
        if (!this._mermaidReady) {
            this._renderQueued = true;
            return;
        }

        let def, nodeCount;
        try {
            ({ def, nodeCount } = this._buildMermaidDef());
        } catch (err) {
            console.error('Flowchart build error:', err);
            this.container.innerHTML = `<div style="color:#f87171;padding:20px;">Flowchart build error: ${this._escapeHtml(String(err))}</div>`;
            return;
        }

        console.log(`[flowchart] Rendering ${nodeCount} nodes, def length: ${def.length}`);

        // Clear container
        this.container.innerHTML = '';

        // Create wrapper with scroll
        const wrapper = document.createElement('div');
        wrapper.style.cssText = 'width:100%;height:100%;overflow:auto;padding:16px;';
        wrapper.className = 'fc-mermaid-wrapper';

        const chartDiv = document.createElement('div');
        chartDiv.className = 'mermaid';
        // Give unique id for mermaid render
        const chartId = 'fc_' + Date.now();

        try {
            const { svg } = await mermaid.render(chartId, def);
            chartDiv.innerHTML = svg;
        } catch (err) {
            console.error('Mermaid render error:', err);
            console.debug('Mermaid def:', def.substring(0, 500));
            chartDiv.innerHTML = `<div style="color:#f87171;padding:20px;">Flowchart render error: ${this._escapeHtml(String(err))}</div>`;
        }

        wrapper.appendChild(chartDiv);
        this.container.appendChild(wrapper);

        // Register global click handler for mermaid nodes
        this._registerClickHandlers(wrapper);

        // Auto-scroll to bottom
        requestAnimationFrame(() => {
            wrapper.scrollTop = wrapper.scrollHeight;
        });
    }

    _registerClickHandlers(wrapper) {
        // Mermaid with securityLevel:'loose' calls window functions
        window.flowchartClickHandler = (nodeId) => {
            const data = this._nodeDataMap[nodeId];
            if (data) {
                this._showPopup(nodeId, data);
            }
        };

        // Also add click listeners to SVG nodes directly for better UX
        const svgEl = wrapper.querySelector('svg');
        if (!svgEl) return;

        const nodes = svgEl.querySelectorAll('.node');
        nodes.forEach(node => {
            node.style.cursor = 'pointer';
            node.addEventListener('click', (e) => {
                e.stopPropagation();
                const nodeId = node.id || '';
                // Mermaid prefixes node IDs with 'flowchart-' and appends a suffix
                // Try to find matching key in our data map
                const matchedKey = this._findNodeDataKey(nodeId);
                if (matchedKey) {
                    const rect = node.getBoundingClientRect();
                    this._showPopupAt(matchedKey, this._nodeDataMap[matchedKey], rect.right + 8, rect.top);
                }
            });
        });

        // Click background to dismiss popup
        wrapper.addEventListener('click', (e) => {
            if (e.target === wrapper || e.target.tagName === 'svg') {
                this._hidePopup();
            }
        });
    }

    _findNodeDataKey(mermaidNodeId) {
        // Mermaid transforms node IDs — try matching by substring
        for (const key of Object.keys(this._nodeDataMap)) {
            if (mermaidNodeId.includes(key)) return key;
        }
        return null;
    }

    // ── Popup ───────────────────────────────────────────────────────

    _showPopup(nodeId, data) {
        // Position near center of viewport
        const x = window.innerWidth / 2 - 200;
        const y = window.innerHeight / 3;
        this._showPopupAt(nodeId, data, x, y);
    }

    _showPopupAt(nodeId, data, x, y) {
        this._hidePopup();

        const popup = document.createElement('div');
        popup.className = 'card fc-popup';
        popup.style.cssText = `
            position: fixed; z-index: 900; max-width: 500px; min-width: 300px;
            padding: 16px 20px; font-size: 0.85rem; pointer-events: auto;
            border: 1px solid var(--border, #1e2d3d); background: var(--bg-secondary, #111820);
            border-radius: 8px; box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            left: ${Math.min(x, window.innerWidth - 520)}px;
            top: ${Math.min(y, window.innerHeight - 400)}px;
            max-height: 70vh; overflow-y: auto;
        `;

        let content = this._buildPopupContent(nodeId, data);

        content += `<button onclick="this.parentElement.remove()" style="
            position:absolute; top:8px; right:10px; background:none; border:none;
            color:var(--text-muted, #6b7280); cursor:pointer; font-size:1.2rem; line-height:1;
        ">&times;</button>`;

        popup.innerHTML = content;
        document.body.appendChild(popup);
        this._popup = popup;

        // Dismiss on Escape
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                this._hidePopup();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    }

    _buildPopupContent(nodeId, data) {
        const h = this._escapeHtml;
        const sectionTitle = (text) => `<div style="font-weight:600;color:var(--text, #c9d1d9);margin-bottom:10px;font-size:0.95rem;">${h(text)}</div>`;
        const field = (label, value) => value ? `<div style="margin-bottom:6px;"><span style="color:var(--text-muted, #6b7280);font-size:0.8rem;">${h(label)}:</span> <span style="color:var(--text, #c9d1d9);">${h(String(value))}</span></div>` : '';
        const codeBlock = (text, maxLen) => {
            const truncated = text && text.length > (maxLen || 500) ? text.substring(0, maxLen || 500) + '...' : (text || '');
            return truncated ? `<pre style="background:var(--bg-tertiary, #0a0e14);padding:8px 10px;border-radius:4px;font-size:0.78rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:var(--text-muted, #9ca3af);margin:6px 0;max-height:200px;overflow-y:auto;">${h(truncated)}</pre>` : '';
        };

        switch (data.type) {
            case 'brain': {
                let c = sectionTitle(`Brain Response - Turn ${data.turn}`);
                c += field('Stop Reason', data.stopReason);
                if (data.toolCalls && data.toolCalls.length) {
                    c += field('Tools Called', data.toolCalls.join(', '));
                }
                if (data.thinking) {
                    c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Thinking:</div>`;
                    c += codeBlock(data.thinking, 800);
                }
                if (data.text) {
                    c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Response:</div>`;
                    c += codeBlock(data.text, 800);
                }
                return c;
            }

            case 'tool': {
                let c = sectionTitle(`Tool: ${data.toolName}`);
                c += field('Turn', data.turn);
                c += field('Tool ID', data.toolId);
                c += field('Elapsed', data.elapsed != null ? `${Math.round(data.elapsed)}ms` : '-');
                c += field('Error', data.isError ? 'Yes' : 'No');
                if (data.input) {
                    c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Input:</div>`;
                    c += codeBlock(data.input, 600);
                }
                if (data.result) {
                    c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Result:</div>`;
                    c += codeBlock(data.result, 1000);
                }
                return c;
            }

            case 'finding': {
                const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#06b6d4' };
                const sevColor = sevColors[data.severity] || '#06b6d4';
                let c = sectionTitle(`Finding: ${data.vulnType}`);
                c += `<div style="margin-bottom:8px;"><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:${sevColor}20;color:${sevColor};border:1px solid ${sevColor};">${h(data.severity.toUpperCase())}</span>`;
                if (data.confirmed) {
                    c += ` <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;background:rgba(34,197,94,0.15);color:#22c55e;border:1px solid #22c55e;">CONFIRMED</span>`;
                }
                c += '</div>';
                c += field('Turn', data.turn);
                c += field('Endpoint', data.endpoint);
                c += field('Finding ID', data.findingId);
                if (data.evidence) {
                    c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Evidence:</div>`;
                    c += codeBlock(data.evidence, 1000);
                }
                return c;
            }

            case 'compression': {
                let c = sectionTitle(`Compression - Tier ${data.tier}`);
                c += field('Turn', data.turn);
                c += field('Before', `${this._formatSize(data.beforeChars)} (${data.messagesBefore || '?'} messages)`);
                c += field('After', `${this._formatSize(data.afterChars)} (${data.messagesAfter || '?'} messages)`);
                const ratio = data.beforeChars && data.afterChars ? Math.round((1 - data.afterChars / data.beforeChars) * 100) : 0;
                c += field('Reduction', `${ratio}%`);
                return c;
            }

            case 'error': {
                let c = sectionTitle('Error');
                c += field('Turn', data.turn);
                c += field('Context', data.context);
                c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Error:</div>`;
                c += codeBlock(data.error, 1000);
                return c;
            }

            case 'memory_save': {
                let c = sectionTitle('Memory Saved');
                c += field('Turn', data.turn);
                c += field('Path', data.memoryPath);
                return c;
            }

            case 'hypothesis': {
                let c = sectionTitle('Hypothesis');
                c += field('Turn', data.turn);
                c += field('Priority', data.priority);
                c += field('Suggested Tool', data.suggestedTool);
                c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Hypothesis:</div>`;
                c += codeBlock(data.hypothesis, 600);
                return c;
            }

            case 'chain': {
                let c = sectionTitle(`Chain: ${data.chainName}`);
                c += field('Turn', data.turn);
                c += field('Severity', data.severity);
                c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Description:</div>`;
                c += codeBlock(data.description, 600);
                return c;
            }

            case 'strategy_reset': {
                let c = sectionTitle('Strategy Reset');
                c += field('Turn', data.turn);
                c += `<div style="color:var(--text-muted, #6b7280);font-size:0.8rem;margin-top:8px;">Reason:</div>`;
                c += codeBlock(data.reason, 400);
                return c;
            }

            case 'collapsed': {
                let c = sectionTitle(data.label);
                c += field('Events', data.eventCount);
                c += field('Findings', data.findings);
                c += field('Errors', data.errors);
                if (data.tools && data.tools.length) {
                    c += field('Tools Used', data.tools.join(', '));
                }
                return c;
            }

            default: {
                return sectionTitle(nodeId) + `<pre style="font-size:0.78rem;color:var(--text-muted);">${h(JSON.stringify(data, null, 2))}</pre>`;
            }
        }
    }

    _hidePopup() {
        if (this._popup) {
            this._popup.remove();
            this._popup = null;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    _groupByTurn(events) {
        const turns = {};
        for (const e of events) {
            const turn = e.turn || 0;
            if (!turns[turn]) turns[turn] = [];
            turns[turn].push(e);
        }
        return turns;
    }

    _pairTools(toolCalls, toolResults) {
        const pairs = [];
        const resultsByName = {};

        // Index results by tool_name
        for (const r of toolResults) {
            const name = r.data && r.data.tool_name ? r.data.tool_name : 'unknown';
            if (!resultsByName[name]) resultsByName[name] = [];
            resultsByName[name].push(r);
        }

        // Match calls to results
        const usedResults = new Set();
        for (const c of toolCalls) {
            const name = c.data && c.data.tool_name ? c.data.tool_name : 'unknown';
            const available = (resultsByName[name] || []).filter((_, i) => !usedResults.has(`${name}_${i}`));
            if (available.length) {
                const idx = (resultsByName[name] || []).indexOf(available[0]);
                usedResults.add(`${name}_${idx}`);
                pairs.push({ call: c, result: available[0] });
            } else {
                pairs.push({ call: c, result: null });
            }
        }

        // Add unmatched results
        for (const [name, results] of Object.entries(resultsByName)) {
            results.forEach((r, i) => {
                if (!usedResults.has(`${name}_${i}`)) {
                    pairs.push({ call: null, result: r });
                }
            });
        }

        return pairs;
    }

    _severityStyle(severity) {
        const map = {
            critical: { fill: '#2a1215', stroke: '#ef4444', color: '#f87171' },
            high:     { fill: '#251a0f', stroke: '#f97316', color: '#fdba74' },
            medium:   { fill: '#231e0d', stroke: '#eab308', color: '#fde047' },
            low:      { fill: '#0f2a1a', stroke: '#22c55e', color: '#86efac' },
            info:     { fill: '#0d1a1f', stroke: '#06b6d4', color: '#67e8f9' },
        };
        return map[severity] || map.info;
    }

    _formatMs(ms) {
        if (ms == null) return '';
        if (ms < 1000) return `${Math.round(ms)}ms`;
        return `${(ms / 1000).toFixed(1)}s`;
    }

    _formatSize(chars) {
        if (!chars) return '?';
        if (chars < 1000) return `${chars}`;
        return `${(chars / 1000).toFixed(0)}K`;
    }

    _sanitizeId(str) {
        // Mermaid node IDs must be alphanumeric + underscore
        return (str || 'x').replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 30);
    }

    _esc(str) {
        // Escape for Mermaid label strings (inside double quotes)
        return (str || '')
            .replace(/\\/g, '\\\\')
            .replace(/"/g, "'")
            .replace(/\n/g, ' ')
            .replace(/\r/g, '')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/#/g, '&#35;')
            .replace(/&(?!lt;|gt;|amp;|#35;)/g, '&amp;')
            .substring(0, 120);
    }

    _escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    destroy() {
        this._hidePopup();
        this.container.innerHTML = '';
        // Clean up global handler
        if (window.flowchartClickHandler) {
            delete window.flowchartClickHandler;
        }
    }
}
