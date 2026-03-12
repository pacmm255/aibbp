/**
 * Proxy page — Burp Suite-style traffic viewer.
 */
const ProxyPage = {
    _traffic: [],
    _total: 0,
    _currentPage: 1,
    _perPage: 100,
    _selectedEntry: null,
    _domains: [],
    _filters: {},
    _wsCallbacks: [],

    async mount(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Proxy Traffic</h1>
                <div style="display:flex;gap:8px;align-items:center;">
                    <select id="proxy-session" style="padding:6px 12px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.85rem;">
                        <option value="">All Sessions</option>
                    </select>
                    <span id="proxy-total" style="color:var(--text-muted);font-size:0.85rem;"></span>
                </div>
            </div>

            <div style="display:flex;gap:16px;height:calc(100vh - 160px);">
                <!-- Left: Domain Tree -->
                <div class="card" style="width:220px;flex-shrink:0;overflow-y:auto;padding:12px;">
                    <div style="margin-bottom:8px;">
                        <input type="text" id="domain-search" placeholder="Search domains..."
                            style="width:100%;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:0.8rem;outline:none;box-sizing:border-box;">
                    </div>
                    <div id="domain-tree" class="domain-tree"></div>
                </div>

                <!-- Right: Traffic + Detail -->
                <div style="flex:1;display:flex;flex-direction:column;min-width:0;">
                    <!-- Filter Bar -->
                    <div class="filter-bar" style="flex-shrink:0;">
                        <select id="pf-method" style="width:80px;">
                            <option value="">Method</option>
                            <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option><option>OPTIONS</option>
                        </select>
                        <input type="number" id="pf-status-min" placeholder="Status min" style="width:90px;" min="100" max="599">
                        <input type="number" id="pf-status-max" placeholder="Status max" style="width:90px;" min="100" max="599">
                        <input type="text" id="pf-content-type" placeholder="Content-Type" style="width:120px;">
                        <input type="text" id="pf-url" placeholder="URL regex" style="width:140px;">
                        <input type="text" id="pf-body" placeholder="Body search" style="width:120px;">
                        <button class="btn btn-primary btn-sm" id="pf-apply">Apply</button>
                        <button class="btn btn-ghost btn-sm" id="pf-clear">Clear</button>
                    </div>

                    <!-- Traffic Table -->
                    <div style="flex:1;overflow:auto;min-height:200px;" id="traffic-table-container">
                        <table class="data-table" id="proxy-table" style="font-size:0.8rem;">
                            <thead><tr>
                                <th style="width:40px">#</th>
                                <th style="width:65px">Method</th>
                                <th>Host</th>
                                <th>Path</th>
                                <th style="width:55px">Status</th>
                                <th style="width:90px">Type</th>
                                <th style="width:55px">Time</th>
                            </tr></thead>
                            <tbody id="proxy-tbody"></tbody>
                        </table>
                    </div>
                    <div class="pagination" id="proxy-pagination" style="flex-shrink:0;"></div>

                    <!-- Request/Response Split -->
                    <div id="proxy-detail" style="display:none;flex-shrink:0;height:300px;border-top:1px solid var(--border);margin-top:8px;">
                        <div style="display:flex;height:100%;">
                            <div style="flex:1;overflow:auto;padding:12px;border-right:1px solid var(--border);">
                                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                                    <span style="font-size:0.8rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;">Request</span>
                                    <button class="btn btn-ghost btn-sm" id="copy-request">Copy</button>
                                </div>
                                <div id="proxy-request" style="font-size:0.8rem;"></div>
                            </div>
                            <div style="flex:1;overflow:auto;padding:12px;">
                                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                                    <span style="font-size:0.8rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;">Response</span>
                                    <button class="btn btn-ghost btn-sm" id="copy-response">Copy</button>
                                </div>
                                <div id="proxy-response" style="font-size:0.8rem;"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Event listeners
        document.getElementById('pf-apply').addEventListener('click', () => this._applyFilters());
        document.getElementById('pf-clear').addEventListener('click', () => this._clearFilters());
        document.getElementById('proxy-session').addEventListener('change', () => {
            // Unsubscribe from old WS channel
            for (const [ch, cb] of this._wsCallbacks) { WS.unsubscribe(ch, cb); }
            this._wsCallbacks = [];

            const sessionId = document.getElementById('proxy-session').value;
            this._filters.session_id = sessionId || undefined;
            this._currentPage = 1;
            this._loadTraffic();

            // Subscribe to new session's WS channel
            if (sessionId) {
                const cb = () => { this._loadTraffic(); };
                WS.subscribe(`proxy_traffic:${sessionId}`, cb);
                this._wsCallbacks.push([`proxy_traffic:${sessionId}`, cb]);
            }
        });
        document.getElementById('domain-search').addEventListener('input', (e) => this._filterDomainTree(e.target.value));

        document.getElementById('copy-request').addEventListener('click', () => {
            this._copyToClipboard('proxy-request');
        });
        document.getElementById('copy-response').addEventListener('click', () => {
            this._copyToClipboard('proxy-response');
        });

        await Promise.all([this._loadDomains(), this._loadTraffic(), this._loadSessions()]);
        this._setupWS();
    },

    async _loadSessions() {
        try {
            // Use the dedicated proxy/sessions endpoint which only returns
            // sessions that actually have proxy traffic (with request counts).
            const data = await API.get('/api/proxy/sessions');
            const sel = document.getElementById('proxy-session');
            if (!sel) return;
            for (const s of (data.sessions || [])) {
                const opt = document.createElement('option');
                opt.value = s.session_id;
                const label = (s.target_url || s.session_id).substring(0, 40);
                const count = s.traffic_count || 0;
                const status = s.status || '?';
                opt.textContent = `${label} (${status}, ${count} req)`;
                sel.appendChild(opt);
            }
        } catch (err) {}
    },

    async _loadDomains() {
        try {
            const data = await API.get('/api/proxy/domains');
            this._domains = Array.isArray(data) ? data : (data.domains || data || []);
            this._renderDomainTree();
        } catch (err) {
            this._domains = [];
        }
    },

    _renderDomainTree(filter = '') {
        const el = document.getElementById('domain-tree');
        if (!el) return;
        const lf = filter.toLowerCase();

        if (!this._domains.length) {
            el.innerHTML = '<div style="color:var(--text-muted);font-size:0.8rem;padding:8px;">No domains</div>';
            return;
        }

        // "All" option
        let html = `<div class="domain-item ${!this._filters.url_pattern ? 'active' : ''}" data-host="">
            <span>All Domains</span>
            <span class="domain-count">${this._domains.reduce((s, d) => s + d.count, 0)}</span>
        </div>`;

        for (const domain of this._domains) {
            if (lf && !domain.host.toLowerCase().includes(lf)) continue;
            html += `<div class="domain-item" data-host="${this._escapeAttr(domain.host)}">
                <span>${this._escape(domain.host)}</span>
                <span class="domain-count">${domain.count}</span>
            </div>`;
            if (domain.paths && domain.paths.length) {
                html += '<div class="domain-children">';
                for (const p of domain.paths.slice(0, 10)) {
                    html += `<div class="domain-item" data-host="${this._escapeAttr(domain.host)}" data-path="${this._escapeAttr(p.path)}">
                        <span>${this._escape(p.path)}</span>
                        <span class="domain-count">${p.count}</span>
                    </div>`;
                }
                html += '</div>';
            }
        }

        el.innerHTML = html;

        el.querySelectorAll('.domain-item').forEach(item => {
            item.addEventListener('click', () => {
                el.querySelectorAll('.domain-item').forEach(i => i.classList.remove('active'));
                item.classList.add('active');
                const host = item.dataset.host;
                const path = item.dataset.path || '';
                if (host) {
                    this._filters.url_pattern = path ? `${host}${path}` : host;
                } else {
                    delete this._filters.url_pattern;
                }
                // Clear the manual URL filter input to avoid conflict
                const urlInput = document.getElementById('pf-url');
                if (urlInput) urlInput.value = '';
                this._currentPage = 1;
                this._loadTraffic();
            });
        });
    },

    _filterDomainTree(q) {
        this._renderDomainTree(q);
    },

    _applyFilters() {
        const method = document.getElementById('pf-method').value;
        const statusMin = document.getElementById('pf-status-min').value;
        const statusMax = document.getElementById('pf-status-max').value;
        const contentType = document.getElementById('pf-content-type').value;
        const url = document.getElementById('pf-url').value;
        const body = document.getElementById('pf-body').value;

        if (method) this._filters.method = method; else delete this._filters.method;
        if (statusMin) this._filters.status_min = parseInt(statusMin); else delete this._filters.status_min;
        if (statusMax) this._filters.status_max = parseInt(statusMax); else delete this._filters.status_max;
        if (contentType) this._filters.content_type = contentType; else delete this._filters.content_type;
        if (url) this._filters.url_pattern = url; else delete this._filters.url_pattern;
        if (body) this._filters.body_search = body; else delete this._filters.body_search;

        // Clear domain tree selection when manual URL filter is applied
        if (url) {
            const domainTree = document.getElementById('domain-tree');
            if (domainTree) {
                domainTree.querySelectorAll('.domain-item').forEach(i => i.classList.remove('active'));
                // Re-activate the "All Domains" entry
                const allItem = domainTree.querySelector('.domain-item[data-host=""]');
                if (allItem) allItem.classList.add('active');
            }
        }

        this._currentPage = 1;
        this._loadTraffic();
    },

    _clearFilters() {
        this._filters = {};
        document.getElementById('pf-method').value = '';
        document.getElementById('pf-status-min').value = '';
        document.getElementById('pf-status-max').value = '';
        document.getElementById('pf-content-type').value = '';
        document.getElementById('pf-url').value = '';
        document.getElementById('pf-body').value = '';
        document.getElementById('proxy-session').value = '';
        this._currentPage = 1;
        this._loadTraffic();
    },

    async _loadTraffic() {
        const params = {
            page: this._currentPage,
            per_page: this._perPage,
            ...this._filters,
        };

        try {
            const data = await API.get('/api/proxy/traffic', params);
            this._traffic = data.traffic || [];
            this._total = data.total || 0;
            document.getElementById('proxy-total').textContent = `${this._total} requests`;
            this._renderTable();
            this._renderPagination(data.pages || 1);
        } catch (err) {
            console.error('Load traffic error:', err);
        }
    },

    _renderTable() {
        const tbody = document.getElementById('proxy-tbody');
        if (!tbody) return;
        if (!this._traffic.length) {
            tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state" style="padding:40px"><p>No traffic entries</p></div></td></tr>';
            return;
        }

        tbody.innerHTML = this._traffic.map((t, i) => {
            let url;
            try { url = new URL(t.url); } catch { url = { hostname: '', pathname: t.url || '' }; }
            const statusColor = (t.status || 0) < 300 ? 'var(--success)' : (t.status || 0) < 400 ? 'var(--info)' : (t.status || 0) < 500 ? 'var(--warning)' : 'var(--danger)';
            return `
                <tr data-id="${t.id}" style="cursor:pointer;" class="${this._selectedEntry && this._selectedEntry.id === t.id ? 'selected' : ''}">
                    <td style="color:var(--text-muted)">${(this._currentPage - 1) * this._perPage + i + 1}</td>
                    <td>${SeverityBadge.methodHtml(t.method)}</td>
                    <td style="color:var(--text-muted);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${this._escape(url.hostname || '')}</td>
                    <td style="color:var(--text);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${this._escape(t.url)}">${this._escape(url.pathname || '')}</td>
                    <td style="color:${statusColor};font-weight:500;">${t.status || '-'}</td>
                    <td style="color:var(--text-muted);font-size:0.75rem;max-width:90px;overflow:hidden;text-overflow:ellipsis;">${this._escape((t.content_type || '').split(';')[0])}</td>
                    <td style="color:var(--text-muted)">${t.duration_ms || 0}ms</td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('tr[data-id]').forEach(tr => {
            tr.addEventListener('click', () => this._selectEntry(parseInt(tr.dataset.id)));
        });
    },

    _renderPagination(totalPages) {
        const el = document.getElementById('proxy-pagination');
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
                this._loadTraffic();
            });
        });
    },

    async _selectEntry(entryId) {
        try {
            const entry = await API.get(`/api/proxy/traffic/${entryId}`);
            this._selectedEntry = entry;
            document.getElementById('proxy-detail').style.display = 'block';

            // Parse headers defensively — they may arrive as JSON strings from the API
            const reqHeaders = typeof entry.request_headers === 'string'
                ? JSON.parse(entry.request_headers || '{}')
                : (entry.request_headers || {});
            const respHeaders = typeof entry.response_headers === 'string'
                ? JSON.parse(entry.response_headers || '{}')
                : (entry.response_headers || {});

            // Parse body if it's a JSON string so SyntaxHighlight can pretty-print it
            let reqBody = entry.request_body;
            if (typeof reqBody === 'string') {
                try { reqBody = JSON.parse(reqBody); } catch { /* keep as string */ }
            }
            let respBody = entry.response_body;
            if (typeof respBody === 'string') {
                try { respBody = JSON.parse(respBody); } catch { /* keep as string */ }
            }

            // Render request
            document.getElementById('proxy-request').innerHTML = SyntaxHighlight.request(
                entry.method, entry.url, reqHeaders, reqBody
            );

            // Render response
            document.getElementById('proxy-response').innerHTML = SyntaxHighlight.response(
                entry.status, respHeaders, respBody
            );

            // Update table selection
            this._renderTable();
        } catch (err) {
            Toast.error('Failed to load traffic entry');
        }
    },

    _copyToClipboard(elementId) {
        const el = document.getElementById(elementId);
        if (!el) return;
        const text = el.textContent || '';
        navigator.clipboard.writeText(text).then(() => Toast.info('Copied to clipboard'));
    },

    _setupWS() {
        // WS subscriptions are now managed by the session change handler.
        // No-op at mount time — user must select a session to subscribe.
    },

    _escapeAttr(str) {
        return (str || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    },

    _escape(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    },

    unmount() {
        for (const [ch, cb] of this._wsCallbacks) { WS.unsubscribe(ch, cb); }
        this._wsCallbacks = [];
    },
};
