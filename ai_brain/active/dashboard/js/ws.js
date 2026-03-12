/**
 * WebSocket client with auto-reconnect and channel subscriptions.
 */
const WS = {
    _ws: null,
    _subs: {},          // channel -> [callback, ...]
    _queue: [],         // messages queued during disconnect
    _reconnectDelay: 1000,
    _maxReconnectDelay: 30000,
    _heartbeatTimer: null,
    _reconnectTimer: null,
    status: 'disconnected',  // connected | connecting | disconnected

    connect(token) {
        if (this._ws && this._ws.readyState <= 1) return;
        this.status = 'connecting';
        this._updateUI();

        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${proto}//${location.host}/ws?token=${encodeURIComponent(token)}`;

        try {
            this._ws = new WebSocket(url);
        } catch (e) {
            this._scheduleReconnect();
            return;
        }

        this._ws.onopen = () => {
            this.status = 'connected';
            this._reconnectDelay = 1000;
            this._updateUI();
            // Re-subscribe to all channels
            const channels = Object.keys(this._subs);
            if (channels.length) {
                this._send({ type: 'subscribe', channels });
            }
            // Flush queue
            while (this._queue.length) {
                this._send(this._queue.shift());
            }
            // Start heartbeat
            this._startHeartbeat();
        };

        this._ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'ping') {
                    this._send({ type: 'pong' });
                    return;
                }
                if (msg.type === 'pong') return;
                if (msg.type === 'event' && msg.channel) {
                    const cbs = this._subs[msg.channel] || [];
                    cbs.forEach(cb => {
                        try { cb(msg.data, msg.channel); } catch (e) { console.error('WS callback error:', e); }
                    });
                    // Also notify wildcard subscribers
                    (this._subs['*'] || []).forEach(cb => {
                        try { cb(msg.data, msg.channel); } catch (e) {}
                    });
                }
            } catch (e) {
                console.error('WS parse error:', e);
            }
        };

        this._ws.onclose = () => {
            this.status = 'disconnected';
            this._updateUI();
            this._stopHeartbeat();
            this._scheduleReconnect();
        };

        this._ws.onerror = () => {
            // onclose will fire after this
        };
    },

    disconnect() {
        this._stopHeartbeat();
        if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
        if (this._ws) {
            this._ws.onclose = null;
            this._ws.close();
        }
        this._ws = null;
        this.status = 'disconnected';
        this._updateUI();
    },

    subscribe(channel, callback) {
        if (!this._subs[channel]) {
            this._subs[channel] = [];
            if (this.status === 'connected') {
                this._send({ type: 'subscribe', channels: [channel] });
            }
        }
        this._subs[channel].push(callback);
    },

    unsubscribe(channel, callback) {
        if (!this._subs[channel]) return;
        if (callback) {
            this._subs[channel] = this._subs[channel].filter(cb => cb !== callback);
        } else {
            delete this._subs[channel];
        }
        if (this.status === 'connected') {
            this._send({ type: 'unsubscribe', channels: [channel] });
        }
    },

    _send(msg) {
        if (this._ws && this._ws.readyState === 1) {
            this._ws.send(JSON.stringify(msg));
        } else {
            this._queue.push(msg);
        }
    },

    _scheduleReconnect() {
        const token = API.getToken();
        if (!token) return;
        this._reconnectTimer = setTimeout(() => {
            this.connect(token);
        }, this._reconnectDelay);
        this._reconnectDelay = Math.min(this._reconnectDelay * 2, this._maxReconnectDelay);
    },

    _startHeartbeat() {
        this._stopHeartbeat();
        this._heartbeatTimer = setInterval(() => {
            this._send({ type: 'ping' });
        }, 30000);
    },

    _stopHeartbeat() {
        if (this._heartbeatTimer) {
            clearInterval(this._heartbeatTimer);
            this._heartbeatTimer = null;
        }
    },

    _updateUI() {
        const dot = document.querySelector('#ws-status .ws-dot');
        const label = document.querySelector('#ws-status .ws-label');
        if (dot) {
            dot.className = 'ws-dot ' + this.status;
        }
        if (label) {
            const labels = { connected: 'Connected', connecting: 'Reconnecting...', disconnected: 'Disconnected' };
            label.textContent = labels[this.status] || 'Disconnected';
        }
    },
};
