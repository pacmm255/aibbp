/**
 * API client with auto-auth and error handling.
 */
const API = {
    _token: null,

    getToken() {
        if (!this._token) {
            this._token = localStorage.getItem('aibbp_token');
        }
        return this._token;
    },

    setToken(token) {
        this._token = token;
        localStorage.setItem('aibbp_token', token);
    },

    clearToken() {
        this._token = null;
        localStorage.removeItem('aibbp_token');
    },

    async _fetch(method, path, body, params) {
        const headers = { 'Content-Type': 'application/json' };
        const token = this.getToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        let url = path;
        if (params) {
            const qs = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) {
                if (v !== null && v !== undefined && v !== '') {
                    qs.set(k, v);
                }
            }
            const qstr = qs.toString();
            if (qstr) url += '?' + qstr;
        }

        const opts = { method, headers };
        if (body && method !== 'GET') {
            opts.body = JSON.stringify(body);
        }

        const resp = await fetch(url, opts);

        if (resp.status === 401) {
            this.clearToken();
            window.location.hash = '#/login';
            throw new Error('Unauthorized');
        }

        if (resp.status === 503) {
            Toast.show('Service unavailable', 'error');
            throw new Error('Service unavailable');
        }

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }

        return resp.json();
    },

    get(path, params) { return this._fetch('GET', path, null, params); },
    post(path, body) { return this._fetch('POST', path, body); },
    del(path) { return this._fetch('DELETE', path); },
};
