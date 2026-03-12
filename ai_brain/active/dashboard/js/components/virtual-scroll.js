/**
 * Virtual scrolling component for large lists.
 * Only renders visible rows + buffer for performance.
 */
class VirtualScroll {
    constructor(container, options = {}) {
        this.container = container;
        this.rowHeight = options.rowHeight || 32;
        this.overscan = options.overscan || 20;
        this.renderRow = options.renderRow || (() => '');
        this.onRowClick = options.onRowClick || null;

        this._data = [];
        this._scrollTop = 0;
        this._containerHeight = 0;
        this._autoScroll = false;

        this._setup();
    }

    _setup() {
        this.container.style.overflow = 'auto';
        this.container.style.position = 'relative';

        // Spacer element (total height)
        this._spacer = document.createElement('div');
        this._spacer.style.position = 'relative';
        this.container.appendChild(this._spacer);

        // Visible rows container
        this._viewport = document.createElement('div');
        this._viewport.style.position = 'absolute';
        this._viewport.style.top = '0';
        this._viewport.style.left = '0';
        this._viewport.style.right = '0';
        this._spacer.appendChild(this._viewport);

        // Scroll handler
        this.container.addEventListener('scroll', () => {
            this._scrollTop = this.container.scrollTop;
            this._containerHeight = this.container.clientHeight;
            this._renderVisible();
        });

        // Initial height
        this._containerHeight = this.container.clientHeight;
    }

    setData(data) {
        this._data = data;
        this._spacer.style.height = (data.length * this.rowHeight) + 'px';
        this._renderVisible();
    }

    appendData(items) {
        const wasAtBottom = this._isAtBottom();
        this._data = this._data.concat(items);
        this._spacer.style.height = (this._data.length * this.rowHeight) + 'px';
        this._renderVisible();
        if (wasAtBottom || this._autoScroll) {
            this.scrollToBottom();
        }
    }

    scrollTo(index) {
        this.container.scrollTop = index * this.rowHeight;
    }

    scrollToBottom() {
        this.container.scrollTop = this.container.scrollHeight;
    }

    setAutoScroll(enabled) {
        this._autoScroll = enabled;
    }

    _isAtBottom() {
        return this.container.scrollTop + this.container.clientHeight >= this.container.scrollHeight - this.rowHeight * 2;
    }

    _renderVisible() {
        const startIdx = Math.max(0, Math.floor(this._scrollTop / this.rowHeight) - this.overscan);
        const visibleCount = Math.ceil(this._containerHeight / this.rowHeight) + this.overscan * 2;
        const endIdx = Math.min(this._data.length, startIdx + visibleCount);

        let html = '';
        for (let i = startIdx; i < endIdx; i++) {
            const top = i * this.rowHeight;
            const rowHtml = this.renderRow(i, this._data[i]);
            html += `<div class="vs-row" data-index="${i}" style="position:absolute;top:${top}px;left:0;right:0;height:${this.rowHeight}px;display:flex;align-items:center;">${rowHtml}</div>`;
        }

        this._viewport.innerHTML = html;

        // Attach click handlers
        if (this.onRowClick) {
            this._viewport.querySelectorAll('.vs-row').forEach(row => {
                row.style.cursor = 'pointer';
                row.addEventListener('click', () => {
                    const idx = parseInt(row.dataset.index);
                    this.onRowClick(idx, this._data[idx]);
                    // Highlight
                    this._viewport.querySelectorAll('.vs-row').forEach(r => r.classList.remove('selected'));
                    row.classList.add('selected');
                });
            });
        }
    }

    destroy() {
        this.container.innerHTML = '';
    }
}
