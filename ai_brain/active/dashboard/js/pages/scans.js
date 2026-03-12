/**
 * Scans page — list view (paginated) + detail view with flowchart and rich terminal.
 */
const ScansPage = {
    _scans: [],
    _totalScans: 0,
    _scanPages: 1,
    _currentScanPage: 1,
    _scansPerPage: 50,
    _currentScan: null,
    _flowchart: null,
    _term: null,
    _wsCallbacks: [],
    _pollInterval: null,

    // ── ANSI escape helpers ──────────────────────────────────────
    _ANSI: {
        reset:      '\x1b[0m',
        bold:       '\x1b[1m',
        dim:        '\x1b[2m',
        cyan:       '\x1b[36m',
        green:      '\x1b[32m',
        red:        '\x1b[31m',
        yellow:     '\x1b[33m',
        white:      '\x1b[37m',
        brightCyan: '\x1b[96m',
        brightGreen:'\x1b[92m',
        brightRed:  '\x1b[91m',
        magenta:    '\x1b[35m',
        brightYellow: '\x1b[93m',
    },

    _ansi(color, text) {
        const c = this._ANSI[color] || this._ANSI.white;
        return `${c}${text}${this._ANSI.reset}`;
    },

    _ansiBold(color, text) {
        const c = this._ANSI[color] || this._ANSI.white;
        return `${this._ANSI.bold}${c}${text}${this._ANSI.reset}`;
    },

    _ansiDim(text) {
        return `${this._ANSI.dim}${text}${this._ANSI.reset}`;
    },

    async mount(container, params) {
        if (params && params.id) {
            await this._mountDetail(container, params.id);
        } else {
            await this._mountList(container);
        }
    },

    // ═══════════════════════════════════════════════════════════════
    //  LIST VIEW (paginated)
    // ═══════════════════════════════════════════════════════════════

    async _mountList(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Scans</h1>
                <div style="display:flex;gap:8px;align-items:center;">
                    <button class="btn btn-primary" id="new-scan-btn" style="font-size:0.85rem;padding:6px 16px;">
                        + New Scan
                    </button>
                    <select id="scan-status-filter" style="padding:6px 12px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.85rem;">
                        <option value="">All Status</option>
                        <option value="running">Running</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                    </select>
                    <span id="scans-total" style="color:var(--text-muted);font-size:0.85rem;"></span>
                </div>
            </div>
            <div id="scans-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;"></div>
            <div id="scans-pagination" class="pagination" style="margin-top:16px;"></div>
            ${this._newScanModalHtml()}
        `;

        document.getElementById('scan-status-filter').addEventListener('change', () => {
            this._currentScanPage = 1;
            this._loadScans();
        });
        document.getElementById('new-scan-btn').addEventListener('click', () => this._openNewScanModal());
        this._initNewScanModal();
        await this._loadScans();
        this._pollInterval = setInterval(() => this._loadScans(), 10000);
    },

    async _loadScans() {
        const status = document.getElementById('scan-status-filter')?.value || '';
        try {
            const data = await API.get('/api/scans', {
                page: this._currentScanPage,
                per_page: this._scansPerPage,
                status: status || undefined,
            });
            this._scans = data.scans || [];
            this._totalScans = data.total || 0;
            this._scanPages = data.pages || 1;
            const totalEl = document.getElementById('scans-total');
            if (totalEl) totalEl.textContent = `${this._totalScans} scans`;
            this._renderScanCards();
            this._renderScanPagination();
        } catch (err) {
            console.error('Load scans error:', err);
        }
    },

    _renderScanCards() {
        const el = document.getElementById('scans-grid');
        if (!el) return;
        if (!this._scans.length) {
            el.innerHTML = '<div class="empty-state" style="grid-column:1/-1;padding:60px"><p>No scans found</p></div>';
            return;
        }
        el.innerHTML = this._scans.map(s => {
            const budgetPct = s.budget_limit ? Math.min(100, (s.budget_spent / s.budget_limit) * 100) : 0;
            const duration = this._duration(s.started_at, s.finished_at);
            return `
                <div class="card" style="cursor:pointer;transition:transform 0.2s;" data-session="${s.session_id}"
                     onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='none'">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="color:var(--text);font-size:0.9rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px;" title="${this._escape(s.target_url)}">${this._escape(s.target_url || s.session_id)}</span>
                        ${SeverityBadge.statusHtml(s.status)}
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:0.8rem;color:var(--text-muted);margin-bottom:12px;">
                        <span>Duration: ${duration}</span>
                        <span>Turns: ${s.turns || 0}</span>
                        <span>Endpoints: ${s.endpoints_count || 0}</span>
                        <span>Brain: ${s.brain_mode || '-'}</span>
                    </div>
                    <div style="display:flex;gap:6px;margin-bottom:10px;">
                        <span style="font-size:0.8rem;color:var(--text-muted)">${s.findings_count || 0} findings</span>
                    </div>
                    <div style="margin-bottom:4px;display:flex;justify-content:space-between;font-size:0.75rem;color:var(--text-muted);">
                        <span>Budget</span>
                        <span>$${(s.budget_spent || 0).toFixed(2)} / $${(s.budget_limit || 0).toFixed(2)}</span>
                    </div>
                    <div style="height:4px;background:var(--bg-tertiary);border-radius:2px;overflow:hidden;">
                        <div style="height:100%;width:${budgetPct}%;background:${budgetPct > 90 ? 'var(--danger)' : 'var(--accent)'};border-radius:2px;transition:width 0.3s;"></div>
                    </div>
                    <div style="margin-top:8px;font-size:0.75rem;color:var(--text-muted);">${this._formatDate(s.started_at)}</div>
                </div>
            `;
        }).join('');

        el.querySelectorAll('.card[data-session]').forEach(card => {
            card.addEventListener('click', () => {
                window.location.hash = `#/scans/${card.dataset.session}`;
            });
        });
    },

    _renderScanPagination() {
        const el = document.getElementById('scans-pagination');
        if (!el) return;
        const totalPages = this._scanPages;
        if (totalPages <= 1) { el.innerHTML = ''; return; }

        let html = '';
        const start = Math.max(1, this._currentScanPage - 3);
        const end = Math.min(totalPages, start + 7);

        if (this._currentScanPage > 1) {
            html += `<button class="page-btn" data-page="${this._currentScanPage - 1}">&laquo;</button>`;
        }
        for (let i = start; i <= end; i++) {
            html += `<button class="page-btn ${i === this._currentScanPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        if (this._currentScanPage < totalPages) {
            html += `<button class="page-btn" data-page="${this._currentScanPage + 1}">&raquo;</button>`;
        }

        el.innerHTML = html;
        el.querySelectorAll('.page-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this._currentScanPage = parseInt(btn.dataset.page);
                this._loadScans();
            });
        });
    },

    // ═══════════════════════════════════════════════════════════════
    //  DETAIL VIEW
    // ═══════════════════════════════════════════════════════════════

    async _mountDetail(container, sessionId) {
        container.innerHTML = `
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
                <a href="#/scans" style="color:var(--text-muted);text-decoration:none;font-size:0.9rem;">&larr; All Scans</a>
                <span id="scan-detail-title" style="font-size:1.1rem;font-weight:600;color:var(--text);"></span>
                <span id="scan-detail-status"></span>
            </div>
            <div style="display:flex;gap:16px;height:calc(100vh - 140px);">
                <!-- Left Panel: Scan Info -->
                <div id="scan-info-panel" class="card" style="width:240px;flex-shrink:0;overflow-y:auto;padding:16px;"></div>
                <!-- Center Panel: Flowchart -->
                <div class="card" style="flex:1;overflow:hidden;display:flex;flex-direction:column;padding:0;">
                    <div style="padding:10px 16px;border-bottom:1px solid var(--border);font-size:0.85rem;color:var(--text-muted);display:flex;justify-content:space-between;">
                        <span>Scan Flow</span>
                    </div>
                    <div id="scan-flowchart" style="flex:1;overflow:hidden;"></div>
                </div>
                <!-- Right Panel: Terminal -->
                <div class="terminal-panel" style="width:420px;flex-shrink:0;display:flex;flex-direction:column;">
                    <div class="terminal-header"><span>Agent Activity</span></div>
                    <div class="terminal-body" id="scan-terminal" style="flex:1;"></div>
                </div>
            </div>
            <!-- Bottom Panel: Proxy Traffic (collapsible) -->
            <div style="margin-top:8px;">
                <button class="btn btn-ghost btn-sm" id="toggle-proxy-panel" style="margin-bottom:8px;">
                    Show Proxy Traffic
                </button>
                <div id="proxy-bottom-panel" style="display:none;">
                    <div class="card" style="max-height:300px;overflow:auto;padding:0;">
                        <table class="data-table" id="scan-proxy-table">
                            <thead><tr>
                                <th style="width:50px">#</th>
                                <th style="width:70px">Method</th>
                                <th>URL</th>
                                <th style="width:60px">Status</th>
                                <th style="width:70px">Time</th>
                            </tr></thead>
                            <tbody id="scan-proxy-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;

        // Toggle proxy panel
        document.getElementById('toggle-proxy-panel').addEventListener('click', function() {
            const panel = document.getElementById('proxy-bottom-panel');
            const hidden = panel.style.display === 'none';
            panel.style.display = hidden ? 'block' : 'none';
            this.textContent = hidden ? 'Hide Proxy Traffic' : 'Show Proxy Traffic';
        });

        // Load scan data
        await this._loadScanDetail(sessionId);

        // Initialize terminal — wait for layout to settle
        await new Promise(r => requestAnimationFrame(r));
        const termContainer = document.getElementById('scan-terminal');
        if (termContainer && typeof Terminal !== 'undefined') {
            try {
                this._term = TerminalComponent.create(termContainer, { fontSize: 12 });
            } catch (e) {
                console.error('Terminal init failed:', e);
            }
        } else if (termContainer) {
            console.warn('xterm.js not loaded — terminal disabled');
            termContainer.innerHTML = '<div style="padding:16px;color:var(--text-muted);">Terminal unavailable (xterm.js not loaded)</div>';
        }

        // Initialize flowchart
        const fcContainer = document.getElementById('scan-flowchart');
        if (fcContainer) {
            try {
                this._flowchart = new FlowchartRenderer(fcContainer);
            } catch (e) {
                console.error('Flowchart init failed:', e);
                fcContainer.innerHTML = '<div style="padding:16px;color:var(--text-muted);">Flowchart unavailable</div>';
            }
        }

        // Load transcript
        await this._loadTranscript(sessionId);
        await this._loadScanProxy(sessionId);

        // WS subscription for live updates
        const progressCb = (data) => {
            if (this._flowchart) this._flowchart.addEvent(data);
            if (this._term) this._renderLiveEvent(data);
        };
        WS.subscribe(`scan_progress:${sessionId}`, progressCb);
        this._wsCallbacks.push([`scan_progress:${sessionId}`, progressCb]);

        // Poll for scan stats updates
        this._pollInterval = setInterval(() => this._loadScanDetail(sessionId), 10000);
    },

    async _loadScanDetail(sessionId) {
        try {
            const scan = await API.get('/api/scans/detail', { session_id: sessionId });
            this._currentScan = scan;
            this._renderScanInfo(scan);
        } catch (err) {
            Toast.error('Failed to load scan');
        }
    },

    _renderScanInfo(s) {
        const titleEl = document.getElementById('scan-detail-title');
        const statusEl = document.getElementById('scan-detail-status');
        const infoEl = document.getElementById('scan-info-panel');
        if (titleEl) titleEl.textContent = s.target_url || s.session_id;
        if (statusEl) statusEl.innerHTML = SeverityBadge.statusHtml(s.status);

        if (!infoEl) return;
        const budgetPct = s.budget_limit ? Math.min(100, ((s.budget_spent || 0) / s.budget_limit) * 100) : 0;
        const duration = this._duration(s.started_at, s.finished_at);
        infoEl.innerHTML = `
            <div style="font-size:0.85rem;">
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Target</div>
                    <div style="color:var(--text);word-break:break-all;">${this._escape(s.target_url || '-')}</div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Session</div>
                    <div style="color:var(--text-muted);font-size:0.8rem;">${this._escape(s.session_id || '-')}</div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Duration</div>
                    <div style="color:var(--text)">${duration}${s.status === 'running' ? ' (live)' : ''}</div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Budget</div>
                    <div style="color:var(--text)">$${(s.budget_spent || 0).toFixed(2)} / $${(s.budget_limit || 0).toFixed(2)}</div>
                    <div style="height:4px;background:var(--bg-tertiary);border-radius:2px;margin-top:4px;overflow:hidden;">
                        <div style="height:100%;width:${budgetPct}%;background:${budgetPct > 90 ? 'var(--danger)' : 'var(--accent)'};border-radius:2px;"></div>
                    </div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Findings</div>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;">
                        <span style="color:var(--text)">${s.findings_count || 0} total</span>
                        <span style="color:var(--success)">${s.confirmed_count || 0} confirmed</span>
                    </div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Turns</div>
                    <div style="color:var(--text)">${s.turns || 0}</div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Endpoints</div>
                    <div style="color:var(--text)">${s.endpoints_count || 0}</div>
                </div>
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Brain Mode</div>
                    <div style="color:var(--accent)">${this._escape(s.brain_mode || '-')}</div>
                </div>
                ${s.models_used && s.models_used.length ? `
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Models</div>
                    <div style="display:flex;gap:4px;flex-wrap:wrap;">${s.models_used.map(m => `<span style="padding:2px 6px;background:var(--bg-tertiary);border-radius:4px;font-size:0.75rem;color:var(--text-muted);">${this._escape(m)}</span>`).join('')}</div>
                </div>` : ''}
                ${s.tech_stack && s.tech_stack.length ? `
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Tech Stack</div>
                    <div style="display:flex;gap:4px;flex-wrap:wrap;">${s.tech_stack.map(t => `<span style="padding:2px 6px;background:var(--bg-tertiary);border-radius:4px;font-size:0.75rem;color:var(--info);">${this._escape(t)}</span>`).join('')}</div>
                </div>` : ''}
                ${s.error ? `
                <div style="margin-bottom:12px;">
                    <div style="color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;margin-bottom:4px;">Error</div>
                    <div style="color:var(--danger);font-size:0.8rem;">${this._escape(s.error)}</div>
                </div>` : ''}
            </div>
        `;
    },

    // ═══════════════════════════════════════════════════════════════
    //  TRANSCRIPT → TERMINAL (rich rendering)
    // ═══════════════════════════════════════════════════════════════

    /**
     * Render a transcript event into the xterm.js terminal.
     * Handles all event types from react_transcript.py JSONL format.
     *
     * Event shape: { ts, turn, event, data: { ... } }
     */
    _renderTranscriptEvent(ev) {
        if (!this._term) return;
        const t = this._term;
        const turn = ev.turn || '?';
        const d = ev.data || {};

        switch (ev.event) {
            case 'session_start':
                this._writeSessionHeader(d);
                break;

            case 'brain_response':
                this._writeBrainResponse(turn, d);
                break;

            case 'tool_call':
                this._writeToolCall(turn, d);
                break;

            case 'tool_result':
                this._writeToolResult(turn, d);
                break;

            case 'compression':
                this._writeCompression(turn, d);
                break;

            case 'error':
                // Skip tool_execution errors — already shown by tool_result with is_error
                if (d.context && d.context.startsWith('tool_execution:')) break;
                this._writeError(turn, d);
                break;

            case 'memory_save':
                TerminalComponent.writeRaw(t,
                    `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('magenta', '\u{1F4BE} Memory saved')}`
                );
                break;

            case 'finding':
                this._writeFinding(turn, d);
                break;

            case 'hypothesis':
                this._writeHypothesis(turn, d);
                break;

            case 'chain_discovery':
                TerminalComponent.writeRaw(t,
                    `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('magenta', '\u{1F517} Chain:')} ${this._ansi('white', d.chain_name || '?')} ${this._ansiDim(`(${d.combined_severity || '?'})`)}`
                );
                if (d.description) {
                    const desc = this._truncate(d.description, 120);
                    TerminalComponent.writeDim(t, `  \u2514\u2500 ${desc}`);
                }
                break;

            case 'strategy_reset':
                TerminalComponent.writeRaw(t,
                    `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('brightYellow', '\u{1F504} Strategy reset:')} ${this._ansiDim(d.reason || '?')}`
                );
                break;

            case 'state_update':
            case 'brain_prompt':
                // Skip — too noisy/large for the terminal
                break;

            case 'session_end':
                TerminalComponent.writeRaw(t, '');
                TerminalComponent.writeRaw(t, this._ansi('cyan', '\u2501'.repeat(48)));
                TerminalComponent.writeRaw(t,
                    `${this._ansi('cyan', '[session]')} ${this._ansi('white', 'Scan complete')} ${this._ansiDim(`(${d.total_turns || '?'} turns)`)}`
                );
                break;

            default:
                // Unknown events — show dimly
                TerminalComponent.writeDim(t, `[turn ${turn}] ${ev.event}: ${JSON.stringify(d).substring(0, 100)}`);
                break;
        }
    },

    _writeSessionHeader(d) {
        const t = this._term;
        const target = d.target_url || '?';
        const session = d.session_id || '?';
        TerminalComponent.writeRaw(t,
            `${this._ansi('cyan', '[session]')} ${this._ansi('white', 'Target:')} ${this._ansiBold('brightCyan', target)} ${this._ansiDim(`(${session})`)}`
        );
        TerminalComponent.writeRaw(t, this._ansi('cyan', '\u2501'.repeat(48)));
    },

    _writeBrainResponse(turn, d) {
        const t = this._term;
        const blocks = d.content_blocks || [];
        const toolCalls = d.tool_calls || [];

        // Extract thinking text and tool_use blocks from content_blocks
        let thinkingText = '';
        const toolUseBlocks = [];

        for (const block of blocks) {
            if (block.type === 'thinking' && block.text) {
                thinkingText = block.text;
            } else if (block.type === 'tool_use') {
                toolUseBlocks.push(block);
            }
        }

        // Determine tool names to display
        const toolNames = toolUseBlocks.length
            ? toolUseBlocks.map(b => b.name || '?')
            : (toolCalls.length ? toolCalls : []);

        if (toolNames.length) {
            // Brain called tools
            TerminalComponent.writeRaw(t,
                `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('brightCyan', '\u{1F9E0} Brain \u2192')} ${this._ansiBold('white', toolNames.join(', '))}`
            );
        } else {
            // Brain response with no tool calls (text-only)
            TerminalComponent.writeRaw(t,
                `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('brightCyan', '\u{1F9E0} Brain thinking...')}`
            );
        }

        // Show thinking excerpt (first meaningful line, truncated)
        if (thinkingText) {
            const excerpt = this._extractThinkingExcerpt(thinkingText, 140);
            if (excerpt) {
                TerminalComponent.writeDim(t, `  \u251C\u2500 Thinking: "${excerpt}"`);
            }
        }

        // Show tool_use input summaries from content_blocks
        for (const tb of toolUseBlocks) {
            const inputSummary = this._summarizeToolInput(tb.name, tb.input);
            if (inputSummary) {
                TerminalComponent.writeDim(t, `  \u2514\u2500 Input: ${inputSummary}`);
            }
        }
    },

    _writeToolCall(turn, d) {
        const t = this._term;
        const name = d.tool_name || '?';
        const inputStr = d.input || '{}';
        const inputSummary = this._summarizeToolInput(name, inputStr);

        TerminalComponent.writeRaw(t,
            `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('yellow', '\u2699')} ${this._ansi('white', name)}`
        );
        if (inputSummary) {
            TerminalComponent.writeDim(t, `  \u2514\u2500 ${inputSummary}`);
        }
    },

    _writeToolResult(turn, d) {
        const t = this._term;
        const name = d.tool_name || '?';
        const isError = d.is_error || false;
        const elapsedMs = d.elapsed_ms || 0;
        const elapsedStr = this._formatElapsed(elapsedMs);
        const resultStr = d.result || '';

        if (isError) {
            // Error result
            TerminalComponent.writeRaw(t,
                `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('red', `\u2716 ${name} \u2192 ERROR`)} ${this._ansiDim(`(${elapsedStr})`)}`
            );
            // Show error detail
            const errDetail = this._extractErrorDetail(resultStr);
            if (errDetail) {
                TerminalComponent.writeRaw(t, `  ${this._ansi('red', `\u2514\u2500 ${errDetail}`)}`);
            }
        } else {
            // Success result
            TerminalComponent.writeRaw(t,
                `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('green', `\u2714 ${name}`)} ${this._ansiDim(`(${elapsedStr})`)}`
            );
            // Show result summary
            const summary = this._summarizeToolResult(name, resultStr);
            if (summary.length) {
                for (const line of summary) {
                    TerminalComponent.writeDim(t, `  ${line}`);
                }
            }
        }
    },

    _writeCompression(turn, d) {
        const t = this._term;
        const tier = d.tier || '?';
        const before = d.before_chars || 0;
        const after = d.after_chars || 0;
        const beforeK = before > 1000 ? `${Math.round(before / 1000)}K` : before;
        const afterK = after > 1000 ? `${Math.round(after / 1000)}K` : after;

        TerminalComponent.writeRaw(t,
            `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('yellow', `\u{1F5DC} Compression tier ${tier}`)} ${this._ansiDim(`(${beforeK} \u2192 ${afterK} chars)`)}`
        );
    },

    _writeError(turn, d) {
        const t = this._term;
        let error = d.error || 'Unknown error';
        const ctx = d.context || '';
        // Clean up empty "tool_name: " errors
        if (error.trim().endsWith(':')) error = error.trim().slice(0, -1) + ' (no details)';
        const errMsg = this._truncate(error, 150);

        TerminalComponent.writeRaw(t,
            `${this._ansi('red', `[turn ${turn}] \u2716 Error${ctx ? ` (${ctx})` : ''}`)}`
        );
        TerminalComponent.writeRaw(t, `  ${this._ansi('red', `\u2514\u2500 ${errMsg}`)}`);
    },

    _writeFinding(turn, d) {
        const t = this._term;
        const vuln = d.vuln_type || '?';
        const sev = (d.severity || '?').toUpperCase();
        const endpoint = d.endpoint || '?';
        const confirmed = d.confirmed;

        const sevColor = sev === 'CRITICAL' || sev === 'HIGH' ? 'brightRed' :
                          sev === 'MEDIUM' ? 'yellow' : 'white';

        TerminalComponent.writeRaw(t,
            `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('brightGreen', `\u{1F6A8} FINDING:`)} ${this._ansi(sevColor, `[${sev}]`)} ${this._ansi('white', vuln)}`
        );
        TerminalComponent.writeDim(t, `  \u251C\u2500 Endpoint: ${endpoint}`);
        if (confirmed !== undefined) {
            const confStr = confirmed ? this._ansi('green', 'confirmed') : this._ansi('yellow', 'unconfirmed');
            TerminalComponent.writeRaw(t, `  ${this._ANSI.dim}\u2514\u2500 Status: ${confStr}`);
        }
    },

    _writeHypothesis(turn, d) {
        const t = this._term;
        const hyp = this._truncate(d.hypothesis || '?', 100);
        const prio = d.priority || 'medium';
        const tool = d.suggested_tool || '';

        TerminalComponent.writeRaw(t,
            `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('magenta', `\u{1F4A1} Hypothesis (${prio}):`)} ${this._ansiDim(hyp)}`
        );
        if (tool) {
            TerminalComponent.writeDim(t, `  \u2514\u2500 Suggested tool: ${tool}`);
        }
    },

    // ── Tool input/result summarization ─────────────────────────

    /**
     * Parse JSON input string and return a human-readable one-liner.
     * Input can be a JSON string or already-parsed object.
     */
    _summarizeToolInput(toolName, inputRaw) {
        let obj;
        if (typeof inputRaw === 'string') {
            try { obj = JSON.parse(inputRaw); } catch { return this._truncate(inputRaw, 100); }
        } else if (typeof inputRaw === 'object' && inputRaw) {
            obj = inputRaw;
        } else {
            return '';
        }

        const parts = [];
        // Tool-specific summaries
        if (toolName === 'send_http_request' || toolName === 'send_raw_http') {
            if (obj.method) parts.push(obj.method);
            if (obj.url) parts.push(obj.url);
            if (obj.headers && Object.keys(obj.headers).length) parts.push(`${Object.keys(obj.headers).length} headers`);
            if (obj.body) parts.push(`body=${this._truncate(typeof obj.body === 'string' ? obj.body : JSON.stringify(obj.body), 60)}`);
            return parts.join(' ') || '';
        }
        if (toolName === 'crawl_target' || toolName === 'navigate_and_extract') {
            if (obj.start_url || obj.url) parts.push(obj.start_url || obj.url);
            if (obj.max_pages) parts.push(`max_pages=${obj.max_pages}`);
            return parts.join(', ') || '';
        }
        if (toolName === 'run_nuclei' || toolName === 'run_sqlmap' || toolName === 'run_dalfox') {
            if (obj.target || obj.url) parts.push(obj.target || obj.url);
            if (obj.templates) parts.push(`templates=${obj.templates}`);
            if (obj.technique) parts.push(`technique=${obj.technique}`);
            return parts.join(', ') || '';
        }
        if (toolName === 'run_custom_exploit') {
            if (obj.language) parts.push(obj.language);
            if (obj.code) parts.push(`${obj.code.split('\n').length} lines`);
            return parts.join(', ') || '';
        }
        if (toolName === 'submit_finding') {
            if (obj.vuln_type) parts.push(obj.vuln_type);
            if (obj.severity) parts.push(`[${obj.severity.toUpperCase()}]`);
            if (obj.endpoint) parts.push(obj.endpoint);
            return parts.join(' ') || '';
        }

        // Generic: show first 3 keys=values
        const keys = Object.keys(obj).slice(0, 3);
        for (const k of keys) {
            const v = obj[k];
            const vStr = typeof v === 'string' ? v : JSON.stringify(v);
            parts.push(`${k}=${this._truncate(vStr, 50)}`);
        }
        if (Object.keys(obj).length > 3) parts.push('...');
        return parts.join(', ');
    },

    /**
     * Parse a tool result string and return an array of summary lines.
     */
    _summarizeToolResult(toolName, resultRaw) {
        if (!resultRaw) return [];
        let obj;
        if (typeof resultRaw === 'string') {
            try { obj = JSON.parse(resultRaw); } catch {
                // Not JSON — show first meaningful line
                const line = this._truncate(resultRaw.trim(), 120);
                return line ? [`\u2514\u2500 ${line}`] : [];
            }
        } else {
            obj = resultRaw;
        }

        const lines = [];

        // navigate_and_extract / crawl_target
        if (toolName === 'navigate_and_extract' || toolName === 'crawl_target') {
            if (obj.url) lines.push(`\u251C\u2500 URL: ${obj.url}`);
            if (obj.title) lines.push(`\u251C\u2500 Title: ${this._truncate(obj.title, 80)}`);
            if (obj.status) lines.push(`\u2514\u2500 Status: ${obj.status}`);
            if (obj.pages_crawled) lines.push(`\u2514\u2500 Pages: ${obj.pages_crawled}`);
            if (obj.endpoints && obj.endpoints.length) lines.push(`\u2514\u2500 Endpoints: ${obj.endpoints.length}`);
            return lines;
        }

        // send_http_request
        if (toolName === 'send_http_request' || toolName === 'send_raw_http') {
            if (obj.method && obj.url) lines.push(`\u251C\u2500 ${obj.method} ${this._truncate(obj.url, 80)}`);
            if (obj.status_code !== undefined) {
                const bodyLen = obj.body_length || (obj.body ? obj.body.length : 0);
                lines.push(`\u2514\u2500 Response: ${obj.status_code}${bodyLen ? ` (${bodyLen} bytes)` : ''}`);
            }
            return lines;
        }

        // run_nuclei / run_sqlmap / run_dalfox
        if (toolName === 'run_nuclei' || toolName === 'run_sqlmap' || toolName === 'run_dalfox') {
            if (obj.findings && obj.findings.length) {
                lines.push(`\u2514\u2500 ${obj.findings.length} finding(s)`);
            } else if (obj.vulnerable !== undefined) {
                lines.push(`\u2514\u2500 Vulnerable: ${obj.vulnerable}`);
            } else {
                lines.push(`\u2514\u2500 No findings`);
            }
            return lines;
        }

        // scan_info_disclosure
        if (toolName === 'scan_info_disclosure') {
            if (obj.findings && obj.findings.length) {
                lines.push(`\u2514\u2500 ${obj.findings.length} disclosure(s) found`);
            } else {
                lines.push(`\u2514\u2500 No disclosures`);
            }
            return lines;
        }

        // submit_finding
        if (toolName === 'submit_finding') {
            if (obj.status) lines.push(`\u2514\u2500 ${obj.status}`);
            if (obj.finding_id) lines.push(`\u2514\u2500 ID: ${obj.finding_id}`);
            return lines;
        }

        // update_knowledge
        if (toolName === 'update_knowledge') {
            if (obj.accepted !== undefined) lines.push(`\u2514\u2500 Accepted: ${obj.accepted}, Rejected: ${obj.rejected || 0}`);
            return lines;
        }

        // Generic: show a few keys
        const keys = Object.keys(obj);
        if (keys.length === 0) return [];
        if (keys.length <= 3) {
            for (const k of keys) {
                const v = obj[k];
                const vStr = typeof v === 'string' ? v : JSON.stringify(v);
                lines.push(`\u2514\u2500 ${k}: ${this._truncate(vStr, 80)}`);
            }
        } else {
            lines.push(`\u2514\u2500 ${keys.length} fields: ${keys.slice(0, 5).join(', ')}${keys.length > 5 ? '...' : ''}`);
        }
        return lines;
    },

    /**
     * Extract a concise error message from a result string.
     */
    _extractErrorDetail(resultRaw) {
        if (!resultRaw) return '';
        // Try JSON parse
        let obj;
        try { obj = JSON.parse(resultRaw); } catch { /* not JSON */ }
        if (obj) {
            let msg = obj.error || obj.message || obj.detail || '';
            // Clean up empty "tool_name: " patterns
            if (typeof msg === 'string' && msg.trim().endsWith(':')) {
                msg = msg.trim().slice(0, -1) + ' (timeout or empty error)';
            }
            if (msg) return this._truncate(msg, 120);
        }
        // Plain string
        let plain = resultRaw.trim();
        if (plain.endsWith(':')) plain = plain.slice(0, -1) + ' (timeout or empty error)';
        return this._truncate(plain, 120);
    },

    /**
     * Extract a short thinking excerpt — skip boilerplate, pick the first insightful sentence.
     */
    _extractThinkingExcerpt(text, maxLen) {
        if (!text) return '';
        // Split into sentences/lines, pick first non-trivial one
        const lines = text.split(/[\n.!?]+/).map(l => l.trim()).filter(l => l.length > 15);
        const excerpt = lines[0] || text.trim();
        return this._truncate(excerpt, maxLen);
    },

    // ── Live WS event rendering ──────────────────────────────────

    /**
     * Render a live WebSocket progress event.
     * These have a simpler structure than transcript events — adapt to match.
     */
    _renderLiveEvent(data) {
        if (!this._term) return;
        const t = this._term;
        const turn = data.turn || '?';

        // If the WS event carries the full transcript event structure (data.event + data.data),
        // delegate to the rich renderer
        if (data.data && typeof data.data === 'object' && data.event) {
            this._renderTranscriptEvent({ turn: data.turn, event: data.event, data: data.data });
            return;
        }

        // Otherwise handle the simpler WS progress format
        if (data.event === 'brain' || data.event === 'brain_start' || data.event === 'brain_response') {
            const tools = data.tools_called || data.tool_calls || [];
            if (tools.length) {
                TerminalComponent.writeRaw(t,
                    `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('brightCyan', '\u{1F9E0} Brain \u2192')} ${this._ansiBold('white', tools.join(', '))}`
                );
            } else {
                TerminalComponent.writeRaw(t,
                    `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('brightCyan', '\u{1F9E0} Brain thinking...')}`
                );
            }
        } else if (data.event === 'tool' || data.event === 'tool_result') {
            const name = data.tool || data.tool_name || 'tool';
            const isError = data.status === 'error' || data.is_error;
            const elapsedMs = data.elapsed_ms || 0;
            const elapsedStr = this._formatElapsed(elapsedMs);
            const findings = data.findings_count ? ` \u2192 ${data.findings_count} findings` : '';

            if (isError) {
                TerminalComponent.writeRaw(t,
                    `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('red', `\u2716 ${name} \u2192 ERROR`)} ${this._ansiDim(`(${elapsedStr})`)}`
                );
            } else {
                TerminalComponent.writeRaw(t,
                    `${this._ansi('cyan', `[turn ${turn}]`)} ${this._ansi('green', `\u2714 ${name}`)}${this._ansi('green', findings)} ${this._ansiDim(`(${elapsedStr})`)}`
                );
            }
        } else if (data.event === 'compress' || data.event === 'compression') {
            const tier = data.tier || '?';
            TerminalComponent.writeRaw(t,
                `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('yellow', `\u{1F5DC} Compression tier ${tier}`)}`
            );
        } else if (data.event === 'finding') {
            const vuln = data.vuln_type || '?';
            const sev = (data.severity || '?').toUpperCase();
            TerminalComponent.writeRaw(t,
                `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('brightGreen', `\u{1F6A8} FINDING: [${sev}] ${vuln}`)}`
            );
        } else if (data.event === 'error') {
            // Skip tool_execution errors — already shown by tool_result
            if (data.context && data.context.startsWith('tool_execution:')) return;
            TerminalComponent.writeRaw(t,
                `${this._ansi('red', `[turn ${turn}] \u2716 Error: ${this._truncate(data.error || data.message || '?', 100)}`)}`
            );
        } else if (data.event === 'memory_save') {
            TerminalComponent.writeRaw(t,
                `${this._ansi('yellow', `[turn ${turn}]`)} ${this._ansi('magenta', '\u{1F4BE} Memory saved')}`
            );
        }
    },

    // ── Transcript loading ────────────────────────────────────────

    async _loadTranscript(sessionId) {
        try {
            const data = await API.get('/api/scans/transcript', { session_id: sessionId });
            const events = data.events || [];
            console.log(`[scans] Loaded ${events.length} transcript events for ${sessionId}`);

            if (events.length && this._flowchart) {
                try {
                    this._flowchart.setEvents(events);
                } catch (err) {
                    console.error('Flowchart render error:', err);
                }
            }
            // Write rich transcript events to terminal
            if (events.length && this._term) {
                for (const e of events) {
                    try { this._renderTranscriptEvent(e); } catch (err) {
                        console.warn('Transcript event render error:', e.event, err);
                    }
                }
                // Auto-scroll to bottom
                try { this._term.scrollToBottom(); } catch {}
            }

            if (!events.length) {
                if (this._term) {
                    TerminalComponent.writeDim(this._term, 'No transcript data available for this scan.');
                }
            }
        } catch (err) {
            console.error('Load transcript error:', err);
            if (this._term) {
                TerminalComponent.writeError(this._term, `Failed to load transcript: ${err.message}`);
            }
        }
    },

    async _loadScanProxy(sessionId) {
        try {
            const data = await API.get('/api/proxy/traffic', { session_id: sessionId, per_page: 200 });
            const tbody = document.getElementById('scan-proxy-tbody');
            if (!tbody) return;
            if (!data.traffic || !data.traffic.length) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">No proxy traffic</td></tr>';
                return;
            }
            tbody.innerHTML = data.traffic.map((t, i) => `
                <tr>
                    <td style="color:var(--text-muted)">${i + 1}</td>
                    <td>${SeverityBadge.methodHtml(t.method)}</td>
                    <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);" title="${this._escape(t.url)}">${this._escape((t.url || '').substring(0, 80))}</td>
                    <td style="color:${(t.status || 0) < 400 ? 'var(--success)' : 'var(--danger)'}">${t.status || '-'}</td>
                    <td style="color:var(--text-muted)">${t.duration_ms || 0}ms</td>
                </tr>
            `).join('');
        } catch (err) {}
    },

    // ── Helpers ──────────────────────────────────────────────────

    _formatElapsed(ms) {
        if (!ms || ms <= 0) return '0s';
        if (ms < 1000) return `${Math.round(ms)}ms`;
        const sec = ms / 1000;
        if (sec < 60) return `${sec.toFixed(1)}s`;
        return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
    },

    _truncate(str, maxLen) {
        if (!str) return '';
        str = String(str);
        if (str.length <= maxLen) return str;
        return str.substring(0, maxLen) + '...';
    },

    _duration(startStr, endStr) {
        if (!startStr) return '-';
        const start = new Date(startStr).getTime();
        const end = endStr ? new Date(endStr).getTime() : Date.now();
        const sec = Math.floor((end - start) / 1000);
        if (sec < 60) return `${sec}s`;
        if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
        return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
    },

    _formatDate(dateStr) {
        if (!dateStr) return '-';
        try { return new Date(dateStr).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
        catch { return dateStr; }
    },

    _escape(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    },

    // ═══════════════════════════════════════════════════════════════
    //  NEW SCAN MODAL
    // ═══════════════════════════════════════════════════════════════

    _newScanModalHtml() {
        const F = (id, label, type, placeholder, dflt, help) =>
            `<div class="ns-field">
                <label for="ns-${id}">${label}</label>
                <input type="${type}" id="ns-${id}" placeholder="${placeholder || ''}" value="${dflt || ''}" class="ns-input">
                ${help ? `<div class="ns-help">${help}</div>` : ''}
            </div>`;
        const C = (id, label, dflt, help) =>
            `<div class="ns-toggle">
                <label>
                    <input type="checkbox" id="ns-${id}" ${dflt ? 'checked' : ''}>
                    <span class="ns-toggle-track"><span class="ns-toggle-thumb"></span></span>
                    <span class="ns-toggle-label">${label}</span>
                </label>
                ${help ? `<div class="ns-help" style="margin-left:44px;">${help}</div>` : ''}
            </div>`;
        const S = (id, label, options, dflt, help) =>
            `<div class="ns-field">
                <label for="ns-${id}">${label}</label>
                <select id="ns-${id}" class="ns-input">
                    ${options.map(o => `<option value="${o.v}" ${o.v === dflt ? 'selected' : ''}>${o.l}</option>`).join('')}
                </select>
                ${help ? `<div class="ns-help">${help}</div>` : ''}
            </div>`;

        return `
        <div id="new-scan-modal" class="ns-overlay" style="display:none;">
            <div class="ns-modal">
                <style>
                    .ns-overlay { position:fixed;inset:0;z-index:800;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:16px; }
                    .ns-modal { width:680px;max-width:100%;max-height:calc(100vh - 32px);display:flex;flex-direction:column;background:var(--bg-secondary);border:1px solid var(--border);border-radius:12px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.5); }
                    .ns-header { padding:20px 24px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-shrink:0; }
                    .ns-header h2 { margin:0;font-size:1.15rem;color:var(--text);font-weight:700; }
                    .ns-body { overflow-y:auto;padding:20px 24px 24px;flex:1; }
                    .ns-field { margin-bottom:12px; }
                    .ns-field label { display:block;font-size:0.78rem;color:var(--text-muted);margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.3px; }
                    .ns-input { width:100%;padding:9px 12px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:0.88rem;box-sizing:border-box;transition:border-color 0.2s,box-shadow 0.2s;outline:none;font-family:inherit; }
                    .ns-input:focus { border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,0.15); }
                    .ns-input::placeholder { color:var(--text-muted);opacity:0.5; }
                    select.ns-input { cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg width='10' height='6' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M0 0l5 6 5-6' fill='%236b7280'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:32px; }
                    .ns-help { font-size:0.72rem;color:var(--text-muted);margin-top:3px;opacity:0.6;line-height:1.3; }
                    .ns-section { display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none;font-size:0.82rem;color:var(--accent);margin:20px 0 12px;padding:8px 0;border-bottom:1px solid var(--border);font-weight:700;text-transform:uppercase;letter-spacing:0.5px; }
                    .ns-section .ns-chevron { transition:transform 0.2s;font-size:0.7rem;opacity:0.6; }
                    .ns-section.ns-collapsed .ns-chevron { transform:rotate(-90deg); }
                    .ns-section-body { overflow:hidden;transition:max-height 0.25s ease,opacity 0.2s;max-height:600px;opacity:1; }
                    .ns-section-body.ns-hidden { max-height:0;opacity:0;margin:0;overflow:hidden; }
                    .ns-row { display:grid;grid-template-columns:1fr 1fr;gap:12px; }
                    .ns-row3 { display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px; }
                    .ns-toggle { margin-bottom:8px; }
                    .ns-toggle label { display:flex;align-items:center;gap:10px;cursor:pointer;font-size:0.85rem;color:var(--text); }
                    .ns-toggle input { display:none; }
                    .ns-toggle-track { position:relative;width:34px;height:18px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:10px;transition:background 0.2s,border-color 0.2s;flex-shrink:0; }
                    .ns-toggle-thumb { position:absolute;top:2px;left:2px;width:12px;height:12px;background:var(--text-muted);border-radius:50%;transition:transform 0.2s,background 0.2s; }
                    .ns-toggle input:checked + .ns-toggle-track { background:var(--accent);border-color:var(--accent); }
                    .ns-toggle input:checked + .ns-toggle-track .ns-toggle-thumb { transform:translateX(16px);background:#fff; }
                    .ns-toggle-label { font-weight:500; }
                    .ns-toggles-grid { display:grid;grid-template-columns:1fr 1fr;gap:4px 16px; }
                    .ns-footer { padding:16px 24px;border-top:1px solid var(--border);display:flex;gap:12px;justify-content:flex-end;flex-shrink:0;background:var(--bg-secondary); }
                    .ns-footer .btn { padding:10px 24px;font-weight:600;border-radius:8px;font-size:0.88rem; }
                    .ns-brain-cards { display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px; }
                    .ns-brain-card { padding:12px 8px;text-align:center;background:var(--bg-tertiary);border:2px solid var(--border);border-radius:10px;cursor:pointer;transition:all 0.2s;font-size:0.82rem;font-weight:600;color:var(--text-muted); }
                    .ns-brain-card:hover { border-color:var(--accent);color:var(--text); }
                    .ns-brain-card.ns-active { border-color:var(--accent);background:rgba(59,130,246,0.1);color:var(--accent); }
                    .ns-brain-card .ns-brain-icon { font-size:1.4rem;margin-bottom:4px; }
                    .ns-brain-card .ns-brain-sub { font-size:0.7rem;font-weight:400;color:var(--text-muted);margin-top:2px; }
                    @media (max-width:600px) {
                        .ns-modal { border-radius:8px; }
                        .ns-body { padding:16px; }
                        .ns-header { padding:16px; }
                        .ns-footer { padding:12px 16px; }
                        .ns-row, .ns-row3 { grid-template-columns:1fr; }
                        .ns-brain-cards { grid-template-columns:1fr 1fr; }
                        .ns-toggles-grid { grid-template-columns:1fr; }
                    }
                </style>

                <!-- Header -->
                <div class="ns-header">
                    <h2>New Scan</h2>
                    <button id="ns-close" class="btn btn-ghost btn-sm" style="font-size:1.3rem;padding:2px 8px;line-height:1;">&times;</button>
                </div>

                <!-- Body -->
                <div class="ns-body">

                    <!-- Target (always visible) -->
                    ${F('target', 'Target URL *', 'url', 'https://example.com', '', '')}
                    <div class="ns-row">
                        ${F('allowed-domains', 'Allowed Domains', 'text', 'example.com, api.example.com', '', 'Comma-separated in-scope domains')}
                        ${F('out-of-scope', 'Out of Scope', 'text', '', '', 'Comma-separated out-of-scope domains')}
                    </div>

                    <!-- Brain Mode -->
                    <div class="ns-section" data-section="brain">
                        <span class="ns-chevron">&#9660;</span> Brain
                    </div>
                    <div class="ns-section-body" data-for="brain">
                        <div class="ns-brain-cards" id="ns-brain-cards">
                            <div class="ns-brain-card ns-active" data-brain="zai">
                                <div class="ns-brain-icon">&#9889;</div>
                                Z.ai GLM-5
                                <div class="ns-brain-sub">Free &bull; Fast</div>
                            </div>
                            <div class="ns-brain-card" data-brain="chatgpt">
                                <div class="ns-brain-icon">&#128172;</div>
                                ChatGPT
                                <div class="ns-brain-sub">Free &bull; GPT-5.3</div>
                            </div>
                            <div class="ns-brain-card" data-brain="claude">
                                <div class="ns-brain-icon">&#129302;</div>
                                Sonnet
                                <div class="ns-brain-sub">~$0.03/turn</div>
                            </div>
                            <div class="ns-brain-card" data-brain="opus">
                                <div class="ns-brain-icon">&#128142;</div>
                                Opus
                                <div class="ns-brain-sub">~$0.10/turn</div>
                            </div>
                        </div>
                        <input type="hidden" id="ns-brain-mode" value="zai">
                        <div id="ns-brain-sub-opts" class="ns-row">
                            <div id="ns-zai-model-wrap">
                                ${S('zai-model', 'Z.ai Model', [
                                    {v:'glm-5', l:'GLM-5 (Best)'},
                                    {v:'glm-4.7', l:'GLM-4.7'},
                                    {v:'glm-4.6v', l:'GLM-4.6v'}
                                ], 'glm-5', '')}
                            </div>
                            <div id="ns-chatgpt-model-wrap" style="display:none;">
                                ${S('chatgpt-model', 'ChatGPT Model', [
                                    {v:'gpt-5-3', l:'GPT-5.3 (Best)'},
                                    {v:'gpt-5-2', l:'GPT-5.2'},
                                    {v:'gpt-5-1', l:'GPT-5.1'},
                                    {v:'gpt-5', l:'GPT-5'},
                                    {v:'gpt-5-mini', l:'GPT-5 Mini'},
                                    {v:'auto', l:'Auto'}
                                ], 'gpt-5-3', '')}
                            </div>
                        </div>
                    </div>

                    <!-- Budget & Limits -->
                    <div class="ns-section" data-section="budget">
                        <span class="ns-chevron">&#9660;</span> Budget & Limits
                    </div>
                    <div class="ns-section-body" data-for="budget">
                        <div class="ns-row3">
                            ${F('budget', 'Budget ($)', 'number', '15', '15', 'Max spend in dollars')}
                            ${F('max-turns', 'Max Turns', 'number', '150', '150', 'Max reasoning turns')}
                            ${F('timeout', 'Timeout (sec)', 'number', '0', '0', '0 = unlimited')}
                        </div>
                        <div class="ns-row3">
                            ${F('max-rss', 'Max RSS (MB)', 'number', '700', '700', 'Memory limit per agent')}
                            ${S('report-format', 'Report Format', [
                                {v:'md', l:'Markdown'},
                                {v:'html', l:'HTML'},
                                {v:'json', l:'JSON'}
                            ], 'md', '')}
                            ${F('output', 'Output Path', 'text', '/tmp/scan_output.json', '', 'JSON output file')}
                        </div>
                    </div>

                    <!-- Behavior -->
                    <div class="ns-section" data-section="behavior">
                        <span class="ns-chevron">&#9660;</span> Behavior
                    </div>
                    <div class="ns-section-body" data-for="behavior">
                        <div class="ns-toggles-grid">
                            ${C('headless', 'Headless Browser', true, '')}
                            ${C('no-app-gate', 'Skip App Gate', false, '')}
                            ${C('dry-run', 'Dry Run (no real attacks)', false, '')}
                            ${C('no-memory', 'Fresh Start (no memory)', false, '')}
                            ${C('force-opus', 'Force Opus (all turns)', false, '')}
                            ${C('force-sonnet', 'Force Sonnet (all turns)', false, '')}
                            ${C('zai-research', 'Z.ai Research (Agent C)', false, '')}
                            ${C('docker-sandbox', 'Docker Sandbox', false, '')}
                        </div>
                    </div>

                    <!-- Proxy & Network -->
                    <div class="ns-section ns-collapsed" data-section="proxy">
                        <span class="ns-chevron">&#9660;</span> Proxy & Network
                    </div>
                    <div class="ns-section-body ns-hidden" data-for="proxy">
                        <div class="ns-row">
                            ${F('upstream-proxy', 'Upstream Proxy', 'text', 'socks5://127.0.0.1:9054', '', 'SOCKS5/HTTP proxy for outbound traffic')}
                            ${F('proxy-port', 'Mitmproxy Port', 'number', '', '0', 'Override port (0 = auto)')}
                        </div>
                        ${C('enable-proxylist', 'Rotating Proxy Pool', false, 'Distribute Z.ai calls across public proxies')}
                        <div class="ns-row3" id="ns-proxylist-opts" style="opacity:0.4;">
                            ${F('proxy-ratelimit', 'Rate Limit (sec)', 'number', '3', '3', 'Per-proxy delay')}
                            ${F('min-proxies', 'Min Proxies', 'number', '10', '10', 'Min before start')}
                            ${F('max-proxies', 'Max Proxies', 'number', '100', '100', 'Max to validate')}
                        </div>
                    </div>

                    <!-- Email -->
                    <div class="ns-section ns-collapsed" data-section="email">
                        <span class="ns-chevron">&#9660;</span> Email (Registration)
                    </div>
                    <div class="ns-section-body ns-hidden" data-for="email">
                        <div class="ns-row3">
                            ${S('email-mode', 'Mode', [
                                {v:'', l:'Disabled'},
                                {v:'imap', l:'IMAP'},
                                {v:'local', l:'Local'}
                            ], 'imap', '')}
                            ${F('email-domain', 'Domain', 'text', 'inbox.lt', 'inbox.lt', '')}
                            ${F('imap-host', 'IMAP Host', 'text', 'mail.inbox.lt', 'mail.inbox.lt', '')}
                        </div>
                        <div class="ns-row3">
                            ${F('imap-user', 'IMAP User', 'text', 'hunter255', 'hunter255', '')}
                            ${F('imap-password', 'IMAP Password', 'password', '', '7J8PbJbSs6', '')}
                            <div class="ns-field" style="display:flex;align-items:flex-end;">
                                ${C('email-plus-addressing', 'Plus Addressing', true, '')}
                            </div>
                        </div>
                    </div>

                    <!-- Headers & CAPTCHA -->
                    <div class="ns-section ns-collapsed" data-section="headers">
                        <span class="ns-chevron">&#9660;</span> Headers & CAPTCHA
                    </div>
                    <div class="ns-section-body ns-hidden" data-for="headers">
                        ${F('headers', 'Custom Headers', 'text', 'X-Bug-Bounty: authorized', '', 'Comma-separated "Name: Value" pairs')}
                        <div class="ns-row">
                            ${F('captcha-api-key', 'CAPTCHA API Key', 'text', '', '', '2captcha / capsolver key')}
                            ${F('captcha-api-url', 'CAPTCHA Service URL', 'text', 'https://2captcha.com', '', '')}
                        </div>
                    </div>

                    <!-- Advanced -->
                    <div class="ns-section ns-collapsed" data-section="advanced">
                        <span class="ns-chevron">&#9660;</span> Advanced
                    </div>
                    <div class="ns-section-body ns-hidden" data-for="advanced">
                        <div class="ns-row">
                            ${F('memory-dir', 'Memory Directory', 'text', '~/.aibbp/targets', '~/.aibbp/targets', '')}
                            ${F('docker-image', 'Docker Image', 'text', 'kalilinux/kali-rolling', 'kalilinux/kali-rolling', '')}
                        </div>
                        <div class="ns-row">
                            ${F('external-tools', 'External Tools', 'text', '', '', 'Path to JSON tool definitions')}
                            ${F('neo4j-uri', 'Neo4j URI', 'text', '', '', 'bolt://host:7687 (empty = disabled)')}
                        </div>
                    </div>
                </div>

                <!-- Footer -->
                <div class="ns-footer">
                    <button id="ns-cancel" class="btn btn-ghost">Cancel</button>
                    <button id="ns-launch" class="btn btn-primary">Launch Scan</button>
                </div>
            </div>
        </div>`;
    },

    _openNewScanModal() {
        const modal = document.getElementById('new-scan-modal');
        if (modal) modal.style.display = 'flex';
    },

    _closeNewScanModal() {
        const modal = document.getElementById('new-scan-modal');
        if (modal) modal.style.display = 'none';
    },

    _initNewScanModal() {
        const closeBtn = document.getElementById('ns-close');
        const cancelBtn = document.getElementById('ns-cancel');
        const launchBtn = document.getElementById('ns-launch');
        const modal = document.getElementById('new-scan-modal');

        if (closeBtn) closeBtn.addEventListener('click', () => this._closeNewScanModal());
        if (cancelBtn) cancelBtn.addEventListener('click', () => this._closeNewScanModal());
        if (modal) modal.addEventListener('click', (e) => {
            if (e.target === modal) this._closeNewScanModal();
        });
        if (launchBtn) launchBtn.addEventListener('click', () => this._launchScan());

        // Escape key closes modal
        this._escHandler = (e) => { if (e.key === 'Escape') this._closeNewScanModal(); };
        document.addEventListener('keydown', this._escHandler);

        // Collapsible sections
        modal.querySelectorAll('.ns-section[data-section]').forEach(sec => {
            sec.addEventListener('click', () => {
                const name = sec.dataset.section;
                const body = modal.querySelector(`.ns-section-body[data-for="${name}"]`);
                if (!body) return;
                const collapsed = sec.classList.toggle('ns-collapsed');
                if (collapsed) { body.classList.add('ns-hidden'); }
                else { body.classList.remove('ns-hidden'); }
            });
        });

        // Brain card selection
        const brainCards = modal.querySelectorAll('.ns-brain-card');
        const brainInput = document.getElementById('ns-brain-mode');
        const zaiWrap = document.getElementById('ns-zai-model-wrap');
        const cgptWrap = document.getElementById('ns-chatgpt-model-wrap');
        brainCards.forEach(card => {
            card.addEventListener('click', () => {
                brainCards.forEach(c => c.classList.remove('ns-active'));
                card.classList.add('ns-active');
                const mode = card.dataset.brain;
                if (brainInput) brainInput.value = mode;
                if (zaiWrap) zaiWrap.style.display = mode === 'zai' ? '' : 'none';
                if (cgptWrap) cgptWrap.style.display = mode === 'chatgpt' ? '' : 'none';
            });
        });

        // Proxy pool toggle
        const proxyListCb = document.getElementById('ns-enable-proxylist');
        const proxyOpts = document.getElementById('ns-proxylist-opts');
        if (proxyListCb && proxyOpts) {
            proxyListCb.addEventListener('change', () => {
                proxyOpts.style.opacity = proxyListCb.checked ? '1' : '0.4';
            });
        }
    },

    async _launchScan() {
        const target = document.getElementById('ns-target')?.value?.trim();
        if (!target) {
            Toast.error('Target URL is required');
            return;
        }

        const val = (id) => document.getElementById(`ns-${id}`)?.value?.trim() || '';
        const num = (id, dflt) => {
            const v = document.getElementById(`ns-${id}`)?.value;
            return v !== '' && v !== undefined ? parseFloat(v) : dflt;
        };
        const checked = (id) => document.getElementById(`ns-${id}`)?.checked || false;
        const csvList = (id) => {
            const v = val(id);
            return v ? v.split(',').map(s => s.trim()).filter(Boolean) : [];
        };

        const brainMode = val('brain-mode');

        const body = {
            target,
            allowed_domains: csvList('allowed-domains'),
            out_of_scope: csvList('out-of-scope'),
            budget: num('budget', 15),
            max_turns: num('max-turns', 150),
            timeout: num('timeout', 0),
            output: val('output') || undefined,
            report_format: val('report-format') || 'md',
            headless: checked('headless'),
            dry_run: checked('dry-run'),
            no_memory: checked('no-memory'),
            no_app_gate: checked('no-app-gate'),
            force_opus: brainMode === 'opus' || checked('force-opus'),
            force_sonnet: checked('force-sonnet'),
            zai: brainMode === 'zai',
            zai_model: val('zai-model') || 'glm-5',
            zai_research: checked('zai-research'),
            chatgpt: brainMode === 'chatgpt',
            chatgpt_model: val('chatgpt-model') || 'gpt-5-3',
            enable_proxylist: checked('enable-proxylist'),
            proxy_ratelimit: num('proxy-ratelimit', 3),
            min_proxies: num('min-proxies', 10),
            max_proxies: num('max-proxies', 100),
            max_rss: num('max-rss', 700),
            upstream_proxy: val('upstream-proxy') || undefined,
            proxy_port: num('proxy-port', 0) || undefined,
            memory_dir: val('memory-dir') || undefined,
            email_domain: val('email-domain') || undefined,
            email_mode: val('email-mode') || undefined,
            imap_host: val('imap-host') || undefined,
            imap_user: val('imap-user') || undefined,
            imap_password: val('imap-password') || undefined,
            email_plus_addressing: checked('email-plus-addressing'),
            header: csvList('headers'),
            captcha_api_key: val('captcha-api-key') || undefined,
            captcha_api_url: val('captcha-api-url') || undefined,
            docker_sandbox: checked('docker-sandbox'),
            docker_image: val('docker-image') || undefined,
            external_tools: val('external-tools') || undefined,
            neo4j_uri: val('neo4j-uri') || undefined,
        };

        // Clean undefined values
        Object.keys(body).forEach(k => { if (body[k] === undefined) delete body[k]; });

        const btn = document.getElementById('ns-launch');
        if (btn) { btn.disabled = true; btn.textContent = 'Launching...'; }

        try {
            const result = await API.post('/api/scans/new', body);
            Toast.show(`Scan launched for ${target} (PID: ${result.pid || '?'})`, 'success');
            this._closeNewScanModal();
            // Refresh scan list after a delay to let the scan register in DB
            setTimeout(() => this._loadScans(), 3000);
            await this._loadScans();
        } catch (err) {
            Toast.error(`Failed to launch scan: ${err.message}`);
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = 'Launch Scan'; }
        }
    },

    unmount() {
        if (this._flowchart) { this._flowchart.destroy(); this._flowchart = null; }
        if (this._term) { TerminalComponent.destroy(this._term); this._term = null; }
        if (this._pollInterval) { clearInterval(this._pollInterval); this._pollInterval = null; }
        if (this._escHandler) { document.removeEventListener('keydown', this._escHandler); this._escHandler = null; }
        for (const [ch, cb] of this._wsCallbacks) { WS.unsubscribe(ch, cb); }
        this._wsCallbacks = [];
    },
};
