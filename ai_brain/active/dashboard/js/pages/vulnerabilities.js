/**
 * Vulnerabilities page — filterable table with detail drawer.
 */
const VulnerabilitiesPage = {
    _currentPage: 1,
    _perPage: 50,
    _sortBy: 'discovered_at',
    _sortDir: 'desc',
    _filters: {},
    _findings: [],
    _total: 0,
    _selectedId: null,
    _drawerTerm: null,
    _wsCallbacks: [],

    async mount(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Vulnerabilities</h1>
                <span id="vuln-total" style="color:var(--text-muted);font-size:0.9rem;"></span>
            </div>

            <div class="filter-bar" id="vuln-filters">
                <select id="f-severity">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select id="f-vuln-type"><option value="">All Types</option></select>
                <select id="f-domain"><option value="">All Domains</option></select>
                <select id="f-confirmed">
                    <option value="">All Status</option>
                    <option value="true">Confirmed</option>
                    <option value="false">Unconfirmed</option>
                </select>
                <select id="f-fp">
                    <option value="">Show All</option>
                    <option value="false">Hide FPs</option>
                    <option value="true">FPs Only</option>
                </select>
                <input type="text" id="f-search" placeholder="Search..." style="min-width:150px;">
                <button class="btn btn-primary btn-sm" id="vuln-apply-btn">Apply</button>
                <button class="btn btn-ghost btn-sm" id="vuln-clear-btn">Clear</button>
            </div>
            <div id="active-filters" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;"></div>

            <div style="overflow-x:auto;">
                <table class="data-table" id="vuln-table">
                    <thead>
                        <tr>
                            <th data-sort="severity" style="width:100px">Severity</th>
                            <th data-sort="vuln_type">Type</th>
                            <th data-sort="domain">Domain</th>
                            <th>Endpoint</th>
                            <th data-sort="confirmed" style="width:90px">Status</th>
                            <th style="width:100px">Confidence</th>
                            <th data-sort="cvss_score" style="width:70px">CVSS</th>
                            <th data-sort="discovered_at" style="width:120px">Discovered</th>
                        </tr>
                    </thead>
                    <tbody id="vuln-tbody"></tbody>
                </table>
            </div>
            <div class="pagination" id="vuln-pagination"></div>

            <div id="vuln-drawer-overlay" class="drawer-overlay" style="display:none;"></div>
            <div id="vuln-drawer" class="drawer" style="display:none;">
                <div class="drawer-header">
                    <div style="display:flex;align-items:center;gap:12px;">
                        <span id="drawer-severity"></span>
                        <span id="drawer-title" style="font-weight:600;font-size:1.1rem;color:var(--text);"></span>
                    </div>
                    <div style="display:flex;align-items:center;gap:12px;">
                        <span id="drawer-cvss"></span>
                        <span id="drawer-confidence"></span>
                        <button class="drawer-close" id="drawer-close">&times;</button>
                    </div>
                </div>
                <div class="drawer-body">
                    <div class="tabs" id="drawer-tabs">
                        <div class="tab active" data-tab="summary">Summary</div>
                        <div class="tab" data-tab="evidence">Evidence</div>
                        <div class="tab" data-tab="reqresp">Request/Response</div>
                        <div class="tab" data-tab="actions">Actions</div>
                    </div>
                    <div id="tab-summary" class="tab-content active"></div>
                    <div id="tab-evidence" class="tab-content"></div>
                    <div id="tab-reqresp" class="tab-content"></div>
                    <div id="tab-actions" class="tab-content"></div>
                </div>
            </div>
        `;

        // Event listeners
        document.getElementById('vuln-apply-btn').addEventListener('click', () => this._applyFilters());
        document.getElementById('vuln-clear-btn').addEventListener('click', () => this._clearFilters());
        document.getElementById('drawer-close').addEventListener('click', () => this._closeDrawer());
        document.getElementById('vuln-drawer-overlay').addEventListener('click', () => this._closeDrawer());

        // Sortable headers
        document.querySelectorAll('#vuln-table th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.sort;
                if (this._sortBy === col) {
                    this._sortDir = this._sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    this._sortBy = col;
                    this._sortDir = 'desc';
                }
                this._loadFindings();
            });
        });

        // Tabs
        document.querySelectorAll('#drawer-tabs .tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('#drawer-tabs .tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.drawer-body .tab-content').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
            });
        });

        // Keyboard
        document.addEventListener('keydown', this._onKeyDown);

        // Load filter options and data
        await this._loadFilterOptions();
        await this._loadFindings();
        this._setupWS();
    },

    async _loadFilterOptions() {
        try {
            const [domains, stats] = await Promise.all([
                API.get('/api/domains').catch(() => ({ domains: [] })),
                API.get('/api/stats').catch(() => ({})),
            ]);

            const domSel = document.getElementById('f-domain');
            if (domSel && domains.domains) {
                for (const d of domains.domains) {
                    const opt = document.createElement('option');
                    opt.value = d;
                    opt.textContent = d;
                    domSel.appendChild(opt);
                }
            }

            const typeSel = document.getElementById('f-vuln-type');
            if (typeSel && stats.by_vuln_type) {
                for (const t of Object.keys(stats.by_vuln_type)) {
                    const opt = document.createElement('option');
                    opt.value = t;
                    opt.textContent = t;
                    typeSel.appendChild(opt);
                }
            }
        } catch (err) {}
    },

    _applyFilters() {
        this._filters = {};
        const sev = document.getElementById('f-severity').value;
        const vt = document.getElementById('f-vuln-type').value;
        const dom = document.getElementById('f-domain').value;
        const conf = document.getElementById('f-confirmed').value;
        const fp = document.getElementById('f-fp').value;
        const search = document.getElementById('f-search').value;

        if (sev) this._filters.severity = sev;
        if (vt) this._filters.vuln_type = vt;
        if (dom) this._filters.domain = dom;
        if (conf !== '') this._filters.confirmed = conf;
        if (fp !== '') this._filters.is_fp = fp;
        if (search) this._filters.search = search;

        this._currentPage = 1;
        this._loadFindings();
        this._renderActiveFilters();
    },

    _clearFilters() {
        this._filters = {};
        document.getElementById('f-severity').value = '';
        document.getElementById('f-vuln-type').value = '';
        document.getElementById('f-domain').value = '';
        document.getElementById('f-confirmed').value = '';
        document.getElementById('f-fp').value = '';
        document.getElementById('f-search').value = '';
        this._currentPage = 1;
        this._loadFindings();
        this._renderActiveFilters();
    },

    _renderActiveFilters() {
        const el = document.getElementById('active-filters');
        if (!el) return;
        const pills = Object.entries(this._filters).map(([k, v]) =>
            `<span class="filter-pill">${k}: ${v} <span class="remove" data-key="${k}">&times;</span></span>`
        ).join('');
        el.innerHTML = pills;
        el.querySelectorAll('.remove').forEach(btn => {
            btn.addEventListener('click', () => {
                delete this._filters[btn.dataset.key];
                this._currentPage = 1;
                this._loadFindings();
                this._renderActiveFilters();
            });
        });
    },

    async _loadFindings() {
        const params = {
            page: this._currentPage,
            per_page: this._perPage,
            ...this._filters,
        };

        try {
            const data = await API.get('/api/findings', params);
            this._findings = data.findings || [];
            this._total = data.total || 0;
            document.getElementById('vuln-total').textContent = `${this._total} findings`;

            // Sort locally (server already sorts by discovered_at)
            if (this._sortBy !== 'discovered_at') {
                this._findings.sort((a, b) => {
                    let va = a[this._sortBy], vb = b[this._sortBy];
                    if (va === null || va === undefined) va = '';
                    if (vb === null || vb === undefined) vb = '';
                    const cmp = typeof va === 'number' ? va - vb : String(va).localeCompare(String(vb));
                    return this._sortDir === 'asc' ? cmp : -cmp;
                });
            }

            this._renderTable();
            this._renderPagination(data.pages || 1);
        } catch (err) {
            console.error('Load findings error:', err);
        }
    },

    _renderTable() {
        const tbody = document.getElementById('vuln-tbody');
        if (!tbody) return;
        if (!this._findings.length) {
            tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state" style="padding:40px"><p>No findings match your filters</p></div></td></tr>';
            return;
        }
        tbody.innerHTML = this._findings.map(f => {
            const status = f.is_false_positive ? '<span style="color:var(--danger)">FP</span>' :
                           f.confirmed ? '<span style="color:var(--success)">Confirmed</span>' :
                           '<span style="color:var(--text-muted)">Pending</span>';
            return `
                <tr data-id="${f.id}" style="cursor:pointer;" class="${f.id === this._selectedId ? 'selected' : ''}">
                    <td>${SeverityBadge.html(f.severity)}</td>
                    <td style="color:var(--text)">${this._escape(f.vuln_type || '')}</td>
                    <td style="color:var(--text-muted)">${this._escape(f.domain || '')}</td>
                    <td style="color:var(--text-muted);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${this._escape(f.endpoint || '')}">${this._escape((f.endpoint || '').substring(0, 50))}</td>
                    <td>${status}</td>
                    <td>${SeverityBadge.confidenceHtml(f.confidence)}</td>
                    <td>${SeverityBadge.cvssHtml(f.cvss_score)}</td>
                    <td style="color:var(--text-muted);font-size:0.8rem;">${this._formatDate(f.discovered_at)}</td>
                </tr>`;
        }).join('');

        // Row click
        tbody.querySelectorAll('tr[data-id]').forEach(tr => {
            tr.addEventListener('click', () => this._openDrawer(tr.dataset.id));
        });
    },

    _renderPagination(totalPages) {
        const el = document.getElementById('vuln-pagination');
        if (!el || totalPages <= 1) { if (el) el.innerHTML = ''; return; }
        let html = '';
        const start = Math.max(1, this._currentPage - 3);
        const end = Math.min(totalPages, start + 7);
        if (this._currentPage > 1) html += `<button class="page-btn" data-page="${this._currentPage - 1}">&laquo;</button>`;
        for (let i = start; i <= end; i++) {
            html += `<button class="page-btn ${i === this._currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        if (this._currentPage < totalPages) html += `<button class="page-btn" data-page="${this._currentPage + 1}">&raquo;</button>`;
        el.innerHTML = html;
        el.querySelectorAll('.page-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this._currentPage = parseInt(btn.dataset.page);
                this._loadFindings();
            });
        });
    },

    async _openDrawer(findingId) {
        this._selectedId = findingId;
        try {
            const f = await API.get(`/api/findings/${findingId}`);
            this._renderDrawer(f);
            document.getElementById('vuln-drawer').style.display = 'flex';
            document.getElementById('vuln-drawer-overlay').style.display = 'block';
            // Re-render table to show selected
            this._renderTable();
        } catch (err) {
            Toast.error('Failed to load finding details');
        }
    },

    _closeDrawer() {
        document.getElementById('vuln-drawer').style.display = 'none';
        document.getElementById('vuln-drawer-overlay').style.display = 'none';
        if (this._drawerTerm) {
            TerminalComponent.destroy(this._drawerTerm);
            this._drawerTerm = null;
        }
        this._selectedId = null;
        this._renderTable();
    },

    _renderDrawer(f) {
        document.getElementById('drawer-severity').innerHTML = SeverityBadge.html(f.severity);
        document.getElementById('drawer-title').textContent = f.title || f.vuln_type || 'Finding';
        document.getElementById('drawer-cvss').innerHTML = SeverityBadge.cvssHtml(f.cvss_score);
        document.getElementById('drawer-confidence').innerHTML = SeverityBadge.confidenceHtml(f.confidence);

        // Reset to Summary tab
        document.querySelectorAll('#drawer-tabs .tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.drawer-body .tab-content').forEach(t => t.classList.remove('active'));
        document.querySelector('#drawer-tabs .tab[data-tab="summary"]').classList.add('active');
        document.getElementById('tab-summary').classList.add('active');

        // Summary tab
        document.getElementById('tab-summary').innerHTML = `
            <div style="display:grid;grid-template-columns:140px 1fr;gap:8px 16px;font-size:0.875rem;">
                <span style="color:var(--text-muted)">Vulnerability Type</span><span style="color:var(--text)">${this._escape(f.vuln_type || '-')}</span>
                <span style="color:var(--text-muted)">Severity</span><span>${SeverityBadge.html(f.severity)}</span>
                <span style="color:var(--text-muted)">CWE</span><span style="color:var(--accent)">${f.cwe_id ? f.cwe_id : '-'}</span>
                <span style="color:var(--text-muted)">Domain</span><span style="color:var(--text)">${this._escape(f.domain || '-')}</span>
                <span style="color:var(--text-muted)">Target URL</span><span style="color:var(--text);word-break:break-all;">${this._escape(f.target_url || '-')}</span>
                <span style="color:var(--text-muted)">Endpoint</span><span style="color:var(--text);word-break:break-all;">${this._escape(f.endpoint || '-')}</span>
                <span style="color:var(--text-muted)">Method</span><span style="color:var(--text)">${f.method || '-'}</span>
                <span style="color:var(--text-muted)">Parameter</span><span style="color:var(--warning)">${this._escape(f.parameter || '-')}</span>
                <span style="color:var(--text-muted)">Tool Used</span><span style="color:var(--text)">${this._escape(f.tool_used || '-')}</span>
                <span style="color:var(--text-muted)">CVSS Score</span><span>${f.cvss_score || '-'} ${f.cvss_vector ? `(${f.cvss_vector})` : ''}</span>
                <span style="color:var(--text-muted)">Discovered</span><span style="color:var(--text)">${this._formatDate(f.discovered_at)}</span>
                <span style="color:var(--text-muted)">Validated At</span><span style="color:var(--text)">${f.validated_at ? this._formatDate(f.validated_at) : '-'}</span>
            </div>
            ${f.description ? `<div style="margin-top:16px;"><h4 style="color:var(--text-muted);font-size:0.8rem;text-transform:uppercase;margin-bottom:6px;">Description</h4><p style="color:var(--text);font-size:0.875rem;line-height:1.6;">${this._escape(f.description)}</p></div>` : ''}
        `;

        // Evidence tab
        let evidenceHtml = '';
        if (f.poc_code) {
            evidenceHtml += `<h4 style="color:var(--text-muted);font-size:0.8rem;text-transform:uppercase;margin-bottom:6px;">Proof of Concept</h4>`;
            evidenceHtml += `<pre class="code-block" style="background:var(--bg-tertiary);padding:12px;border-radius:6px;overflow-x:auto;color:var(--warning);font-size:0.85rem;">${this._escape(f.poc_code)}</pre>`;
        }
        if (f.steps_to_reproduce && f.steps_to_reproduce.length) {
            evidenceHtml += `<h4 style="color:var(--text-muted);font-size:0.8rem;text-transform:uppercase;margin:16px 0 6px;">Steps to Reproduce</h4>`;
            evidenceHtml += '<ol style="padding-left:20px;color:var(--text);font-size:0.875rem;line-height:1.8;">';
            for (const step of f.steps_to_reproduce) {
                evidenceHtml += `<li>${this._escape(step)}</li>`;
            }
            evidenceHtml += '</ol>';
        }
        if (f.evidence) {
            evidenceHtml += `<h4 style="color:var(--text-muted);font-size:0.8rem;text-transform:uppercase;margin:16px 0 6px;">Evidence Data</h4>`;
            evidenceHtml += SyntaxHighlight.json(f.evidence);
        }
        document.getElementById('tab-evidence').innerHTML = evidenceHtml || '<div class="empty-state" style="padding:20px"><p>No evidence data</p></div>';

        // Request/Response tab
        const highlights = [];
        if (f.parameter) highlights.push({ pattern: f.parameter, class: 'highlight-injection' });
        if (f.poc_code && f.poc_code.length < 100) highlights.push({ pattern: f.poc_code, class: 'highlight-injection' });

        let reqRespHtml = '<div style="display:flex;flex-direction:column;gap:16px;">';
        reqRespHtml += '<div><h4 style="color:var(--text-muted);font-size:0.8rem;text-transform:uppercase;margin-bottom:6px;">Request</h4>';
        if (f.request_dump) {
            reqRespHtml += SyntaxHighlight.http(f.request_dump, highlights);
        } else {
            reqRespHtml += SyntaxHighlight.request(f.method, f.endpoint, {}, null, highlights);
        }
        reqRespHtml += '</div>';

        reqRespHtml += '<div><h4 style="color:var(--text-muted);font-size:0.8rem;text-transform:uppercase;margin-bottom:6px;">Response</h4>';
        if (f.response_dump) {
            const respHighlights = [...highlights];
            if (f.poc_code) respHighlights.push({ pattern: f.poc_code, class: 'highlight-reflected' });
            reqRespHtml += SyntaxHighlight.http(f.response_dump, respHighlights);
        } else {
            reqRespHtml += '<pre class="code-block"><code>No response data captured</code></pre>';
        }
        reqRespHtml += '</div></div>';
        document.getElementById('tab-reqresp').innerHTML = reqRespHtml;

        // Actions tab
        const statusText = f.is_false_positive ? 'False Positive' : f.confirmed ? 'Confirmed' : 'Pending';
        const statusColor = f.is_false_positive ? 'var(--danger)' : f.confirmed ? 'var(--success)' : 'var(--text-muted)';
        document.getElementById('tab-actions').innerHTML = `
            <div style="margin-bottom:24px;">
                <span style="font-size:0.85rem;color:var(--text-muted);">Current Status: </span>
                <span style="font-weight:600;color:${statusColor}">${statusText}</span>
            </div>
            <div style="display:flex;gap:12px;margin-bottom:24px;">
                <button class="btn btn-success" id="action-confirm">Confirm Finding</button>
                <button class="btn btn-danger" id="action-fp">Mark False Positive</button>
                <button class="btn btn-primary" id="action-revalidate">Revalidate</button>
            </div>
            <div id="fp-reason-section" style="display:none;margin-bottom:16px;">
                <textarea id="fp-reason" rows="3" placeholder="Reason for marking as false positive..."
                    style="width:100%;padding:10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.85rem;resize:vertical;box-sizing:border-box;"></textarea>
                <button class="btn btn-danger btn-sm" id="fp-submit" style="margin-top:8px;">Submit</button>
            </div>
            <div id="revalidation-terminal" class="terminal-panel" style="display:none;">
                <div class="terminal-header"><span>Revalidation Output</span></div>
                <div class="terminal-body" id="reval-term-body" style="height:300px;"></div>
            </div>
        `;

        // Action handlers
        document.getElementById('action-confirm').addEventListener('click', async () => {
            try {
                await API.post(`/api/findings/${f.id}/confirm`);
                Toast.success('Finding confirmed');
                this._loadFindings();
                this._openDrawer(f.id);
            } catch (err) { Toast.error(err.message); }
        });

        document.getElementById('action-fp').addEventListener('click', () => {
            document.getElementById('fp-reason-section').style.display = 'block';
        });

        document.getElementById('fp-submit').addEventListener('click', async () => {
            const reason = document.getElementById('fp-reason').value;
            try {
                await API.post(`/api/findings/${f.id}/false-positive`, { reason });
                Toast.success('Marked as false positive');
                this._loadFindings();
                this._openDrawer(f.id);
            } catch (err) { Toast.error(err.message); }
        });

        document.getElementById('action-revalidate').addEventListener('click', async () => {
            const termPanel = document.getElementById('revalidation-terminal');
            termPanel.style.display = 'block';

            if (this._drawerTerm) TerminalComponent.destroy(this._drawerTerm);
            this._drawerTerm = TerminalComponent.create(document.getElementById('reval-term-body'));

            // Subscribe to revalidation WS channel
            const channel = `revalidation:${f.id}`;
            const termRef = this._drawerTerm;
            WS.subscribe(channel, (data) => {
                if (data.type === 'output') {
                    TerminalComponent.writeLine(termRef, data.text, data.color || 'white');
                } else if (data.type === 'complete') {
                    if (data.result === 'confirmed') {
                        TerminalComponent.writeSuccess(termRef, '\n  CONFIRMED ✓');
                    } else if (data.result === 'false_positive') {
                        TerminalComponent.writeError(termRef, '\n  FALSE POSITIVE ✗');
                    } else {
                        TerminalComponent.writeWarning(termRef, '\n  INCONCLUSIVE ?');
                    }
                    this._loadFindings();
                    WS.unsubscribe(channel);
                } else if (data.type === 'error') {
                    TerminalComponent.writeError(termRef, `\n  Error: ${data.error}`);
                    WS.unsubscribe(channel);
                }
            });

            try {
                await API.post(`/api/findings/${f.id}/revalidate`);
                TerminalComponent.writeInfo(this._drawerTerm, 'Revalidation started...\n');
            } catch (err) {
                TerminalComponent.writeError(this._drawerTerm, `Failed to start: ${err.message}`);
            }
        });
    },

    _setupWS() {
        const cb = () => { this._loadFindings(); };
        WS.subscribe('findings', cb);
        this._wsCallbacks.push(['findings', cb]);
    },

    _onKeyDown(e) {
        if (e.key === 'Escape') {
            const page = VulnerabilitiesPage;
            if (page._selectedId) page._closeDrawer();
        }
    },

    _formatDate(dateStr) {
        if (!dateStr) return '-';
        try {
            return new Date(dateStr).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch { return dateStr; }
    },

    _escape(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    },

    unmount() {
        document.removeEventListener('keydown', this._onKeyDown);
        if (this._drawerTerm) {
            TerminalComponent.destroy(this._drawerTerm);
            this._drawerTerm = null;
        }
        for (const [ch, cb] of this._wsCallbacks) {
            WS.unsubscribe(ch, cb);
        }
        this._wsCallbacks = [];
    },
};
