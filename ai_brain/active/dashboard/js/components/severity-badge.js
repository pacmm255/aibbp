/**
 * Reusable severity badge HTML generator.
 */
const SeverityBadge = {
    html(severity) {
        const s = (severity || 'info').toLowerCase();
        return `<span class="severity-badge severity-${s}">${s}</span>`;
    },

    statusHtml(status) {
        const s = (status || 'unknown').toLowerCase();
        return `<span class="status-badge status-${s}">${s}</span>`;
    },

    methodHtml(method) {
        const m = (method || 'GET').toUpperCase();
        return `<span class="method-pill method-${m}">${m}</span>`;
    },

    cvssHtml(score) {
        if (score === null || score === undefined) return '<span class="cvss-score cvss-low">-</span>';
        const n = parseFloat(score);
        let cls = 'cvss-low';
        if (n >= 9) cls = 'cvss-critical';
        else if (n >= 7) cls = 'cvss-high';
        else if (n >= 4) cls = 'cvss-medium';
        return `<span class="cvss-score ${cls}">${n.toFixed(1)}</span>`;
    },

    confidenceHtml(confidence) {
        const pct = Math.min(100, Math.max(0, confidence || 0));
        const color = pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
        return `<span class="confidence-meter">
            <span class="confidence-bar"><span class="confidence-fill" style="width:${pct}%;background:${color}"></span></span>
            <span style="font-size:0.8rem;color:var(--text-muted)">${pct}%</span>
        </span>`;
    },
};
