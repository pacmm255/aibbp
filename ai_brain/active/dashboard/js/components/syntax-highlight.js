/**
 * Syntax highlighting for HTTP requests/responses with custom highlights.
 */
const SyntaxHighlight = {
    /**
     * Highlight HTTP text with optional pattern highlights.
     * @param {string} text - Raw HTTP text
     * @param {Array} highlights - [{pattern: "regex", class: "highlight-injection|highlight-reflected|highlight-auth"}]
     * @returns {string} HTML string
     */
    http(text, highlights = []) {
        if (!text) return '<pre class="code-block"><code>No data available</code></pre>';

        let escaped = this._escape(text);

        // Apply custom highlights
        for (const h of highlights) {
            try {
                const regex = new RegExp(this._escapeRegex(h.pattern), 'gi');
                escaped = escaped.replace(regex, `<span class="${h.class}">$&</span>`);
            } catch (e) { /* invalid regex, skip */ }
        }

        return `<pre class="code-block"><code>${escaped}</code></pre>`;
    },

    /**
     * Format and highlight a raw HTTP request.
     */
    request(method, url, headers, body, highlights = []) {
        let text = `${method || 'GET'} ${url || '/'} HTTP/1.1\n`;
        if (headers) {
            for (const [k, v] of Object.entries(headers)) {
                text += `${k}: ${v}\n`;
            }
        }
        if (body) {
            text += '\n';
            if (typeof body === 'string') {
                try {
                    text += JSON.stringify(JSON.parse(body), null, 2);
                } catch {
                    text += body;
                }
            } else {
                text += JSON.stringify(body, null, 2);
            }
        }
        return this.http(text, highlights);
    },

    /**
     * Format and highlight a raw HTTP response.
     */
    response(status, headers, body, highlights = []) {
        let text = `HTTP/1.1 ${status || '?'}\n`;
        if (headers) {
            for (const [k, v] of Object.entries(headers)) {
                text += `${k}: ${v}\n`;
            }
        }
        if (body) {
            text += '\n';
            if (typeof body === 'string') {
                try {
                    text += JSON.stringify(JSON.parse(body), null, 2);
                } catch {
                    text += body;
                }
            } else {
                text += JSON.stringify(body, null, 2);
            }
        }
        return this.http(text, highlights);
    },

    json(obj) {
        const str = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
        const escaped = this._escape(str);
        if (window.Prism && Prism.languages.json) {
            const highlighted = Prism.highlight(str, Prism.languages.json, 'json');
            return `<pre class="code-block language-json"><code>${highlighted}</code></pre>`;
        }
        return `<pre class="code-block language-json"><code>${escaped}</code></pre>`;
    },

    _escape(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    _escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    },
};
