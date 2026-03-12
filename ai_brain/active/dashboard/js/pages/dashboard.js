/**
 * Dashboard page — stats, charts, recent findings, active agents.
 */
const DashboardPage = {
    _charts: [],
    _wsCallbacks: [],
    _agentInterval: null,

    async mount(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Dashboard</h1>
            </div>

            <div class="stats-grid" id="stats-grid">
                <div class="stat-card accent skeleton-card"><div class="stat-value" id="stat-total">-</div><div class="stat-label">Total Findings</div></div>
                <div class="stat-card success skeleton-card"><div class="stat-value" id="stat-confirmed">-</div><div class="stat-label">Confirmed</div></div>
                <div class="stat-card critical skeleton-card"><div class="stat-value" id="stat-fp">-</div><div class="stat-label">False Positives</div></div>
                <div class="stat-card critical skeleton-card"><div class="stat-value" id="stat-critical">-</div><div class="stat-label">Critical</div></div>
                <div class="stat-card high skeleton-card"><div class="stat-value" id="stat-high">-</div><div class="stat-label">High</div></div>
                <div class="stat-card info skeleton-card"><div class="stat-value" id="stat-agents">-</div><div class="stat-label">Active Agents</div></div>
            </div>

            <div class="charts-grid">
                <div class="card chart-card"><div class="card-header"><span class="card-title">Findings Over Time</span></div><div id="chart-timeline"></div></div>
                <div class="card chart-card"><div class="card-header"><span class="card-title">By Severity</span></div><div id="chart-severity"></div></div>
                <div class="card chart-card"><div class="card-header"><span class="card-title">By Vulnerability Type</span></div><div id="chart-vuln-type"></div></div>
                <div class="card chart-card"><div class="card-header"><span class="card-title">By Domain</span></div><div id="chart-domain"></div></div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                <div class="card">
                    <div class="card-header"><span class="card-title">Recent Findings</span></div>
                    <div id="recent-findings"></div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Active Agents</span></div>
                    <div id="active-agents"></div>
                </div>
            </div>
        `;

        await this._loadData();
        this._setupWS();
        this._agentInterval = setInterval(() => this._loadAgents(), 15000);
    },

    async _loadData() {
        try {
            const [stats, timeline, agents] = await Promise.all([
                API.get('/api/stats'),
                API.get('/api/findings/timeline', { days: 30 }).catch(() => []),
                API.get('/api/agents').catch(() => ({ agents: [] })),
            ]);

            // Animate stat cards
            this._animateCount('stat-total', stats.total || 0);
            this._animateCount('stat-confirmed', stats.confirmed || 0);
            this._animateCount('stat-fp', stats.false_positives || 0);
            this._animateCount('stat-critical', (stats.by_severity || {}).critical || 0);
            this._animateCount('stat-high', (stats.by_severity || {}).high || 0);
            this._animateCount('stat-agents', (agents.agents || []).length);

            // Remove skeleton
            document.querySelectorAll('.skeleton-card').forEach(el => el.classList.remove('skeleton-card'));

            // Charts
            this._renderCharts(stats, timeline);
            this._renderRecentFindings();
            this._renderAgents(agents.agents || []);
        } catch (err) {
            console.error('Dashboard load error:', err);
        }
    },

    _animateCount(id, target) {
        const el = document.getElementById(id);
        if (!el) return;
        const duration = 600;
        const start = performance.now();
        const from = 0;
        const step = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(from + (target - from) * eased);
            if (progress < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    },

    _renderCharts(stats, timeline) {
        // Findings over time
        const timelineEl = document.getElementById('chart-timeline');
        if (timelineEl && timeline && timeline.length) {
            const dates = timeline.map(t => t.date);
            const counts = timeline.map(t => t.count);
            this._charts.push(Charts.area(timelineEl, {
                series: [{ name: 'Findings', data: counts }],
                xaxis: { categories: dates, labels: { style: { colors: '#6b7280' } } },
            }));
        } else if (timelineEl) {
            timelineEl.innerHTML = '<div class="empty-state"><p>No timeline data yet</p></div>';
        }

        // By severity
        const sevEl = document.getElementById('chart-severity');
        if (sevEl && stats.by_severity) {
            const labels = Object.keys(stats.by_severity);
            const values = Object.values(stats.by_severity);
            if (values.some(v => v > 0)) {
                const colorMap = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#06b6d4' };
                this._charts.push(Charts.donut(sevEl, {
                    series: values,
                    labels: labels,
                    colors: labels.map(l => colorMap[l] || '#6b7280'),
                }));
            } else {
                sevEl.innerHTML = '<div class="empty-state"><p>No severity data</p></div>';
            }
        }

        // By vuln type
        const vulnEl = document.getElementById('chart-vuln-type');
        if (vulnEl && stats.by_vuln_type) {
            const entries = Object.entries(stats.by_vuln_type).slice(0, 10);
            if (entries.length) {
                this._charts.push(Charts.bar(vulnEl, {
                    series: [{ name: 'Count', data: entries.map(e => e[1]) }],
                    xaxis: { categories: entries.map(e => e[0]) },
                }));
            } else {
                vulnEl.innerHTML = '<div class="empty-state"><p>No vulnerability data</p></div>';
            }
        }

        // By domain
        const domEl = document.getElementById('chart-domain');
        if (domEl && stats.by_domain) {
            const entries = Object.entries(stats.by_domain).slice(0, 15);
            if (entries.length) {
                this._charts.push(Charts.treemap(domEl, {
                    series: [{ data: entries.map(([name, val]) => ({ x: name, y: val })) }],
                }));
            } else {
                domEl.innerHTML = '<div class="empty-state"><p>No domain data</p></div>';
            }
        }
    },

    async _renderRecentFindings() {
        const el = document.getElementById('recent-findings');
        if (!el) return;
        try {
            const data = await API.get('/api/findings', { per_page: 10 });
            if (!data.findings || !data.findings.length) {
                el.innerHTML = '<div class="empty-state" style="padding:20px"><p>No findings yet</p></div>';
                return;
            }
            el.innerHTML = data.findings.map(f => `
                <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);">
                    ${SeverityBadge.html(f.severity)}
                    <span style="flex:1;color:var(--text);font-size:0.85rem;">${this._escape(f.vuln_type || '')} — ${this._escape((f.endpoint || '').substring(0, 40))}</span>
                    <span style="color:var(--text-muted);font-size:0.8rem;">${f.domain || ''}</span>
                    <span style="color:var(--text-muted);font-size:0.75rem;">${this._timeAgo(f.discovered_at)}</span>
                </div>
            `).join('');
        } catch (err) {
            el.innerHTML = '<div class="empty-state" style="padding:20px"><p>Failed to load</p></div>';
        }
    },

    async _loadAgents() {
        try {
            const data = await API.get('/api/agents');
            this._renderAgents(data.agents || []);
            const agentEl = document.getElementById('stat-agents');
            if (agentEl) agentEl.textContent = (data.agents || []).length;
        } catch (err) {}
    },

    _renderAgents(agents) {
        const el = document.getElementById('active-agents');
        if (!el) return;
        if (!agents.length) {
            el.innerHTML = '<div class="empty-state" style="padding:20px"><p>No active agents</p></div>';
            return;
        }
        el.innerHTML = agents.map(a => `
            <div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);">
                <span class="ws-dot connected" style="flex-shrink:0"></span>
                <div style="flex:1;min-width:0;">
                    <div style="color:var(--text);font-size:0.85rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${this._escape(a.target || a.session_id || '?')}</div>
                    <div style="color:var(--text-muted);font-size:0.75rem;">Turn ${a.turn || '?'} · ${a.findings || 0} findings · TTL ${a.ttl_seconds || '?'}s</div>
                </div>
            </div>
        `).join('');
    },

    _setupWS() {
        const cb = () => { this._loadData(); };
        WS.subscribe('findings', cb);
        this._wsCallbacks.push(['findings', cb]);
    },

    _timeAgo(dateStr) {
        if (!dateStr) return '';
        const diff = (Date.now() - new Date(dateStr).getTime()) / 1000;
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    },

    _escape(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    },

    unmount() {
        for (const chart of this._charts) {
            try { chart.destroy(); } catch (e) {}
        }
        this._charts = [];
        for (const [ch, cb] of this._wsCallbacks) {
            WS.unsubscribe(ch, cb);
        }
        this._wsCallbacks = [];
        if (this._agentInterval) {
            clearInterval(this._agentInterval);
            this._agentInterval = null;
        }
    },
};
