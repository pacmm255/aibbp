/**
 * xterm.js terminal component wrapper.
 */
const TerminalComponent = {
    create(container, options = {}) {
        const term = new window.Terminal({
            theme: {
                background: '#0a0e14',
                foreground: '#c9d1d9',
                cursor: '#3b82f6',
                green: '#22c55e',
                cyan: '#06b6d4',
                red: '#ef4444',
                yellow: '#eab308',
                white: '#c9d1d9',
                brightGreen: '#4ade80',
                brightCyan: '#22d3d1',
                brightRed: '#f87171',
                brightYellow: '#facc15',
            },
            fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", monospace',
            fontSize: 13,
            lineHeight: 1.4,
            cursorBlink: false,
            disableStdin: true,
            scrollback: 5000,
            convertEol: true,
            ...options,
        });

        term.open(container);

        // Fit to container
        try {
            const fitAddon = new window.FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            fitAddon.fit();
            // Re-fit on resize
            const observer = new ResizeObserver(() => {
                try { fitAddon.fit(); } catch (e) {}
            });
            observer.observe(container);
            term._fitAddon = fitAddon;
            term._resizeObserver = observer;
        } catch (e) {
            console.warn('xterm fit addon not available:', e);
        }

        return term;
    },

    writeLine(term, text, color = 'white') {
        const colors = {
            green: '\x1b[32m',
            cyan: '\x1b[36m',
            red: '\x1b[31m',
            yellow: '\x1b[33m',
            white: '\x1b[37m',
            brightgreen: '\x1b[92m',
            brightcyan: '\x1b[96m',
            brightred: '\x1b[91m',
        };
        const code = colors[color.toLowerCase()] || colors.white;
        term.writeln(`${code}${text}\x1b[0m`);
    },

    writeSuccess(term, text) { this.writeLine(term, text, 'green'); },
    writeError(term, text) { this.writeLine(term, text, 'red'); },
    writeInfo(term, text) { this.writeLine(term, text, 'cyan'); },
    writeWarning(term, text) { this.writeLine(term, text, 'yellow'); },

    /** Write dim/grey text (ANSI dim attribute). */
    writeDim(term, text) {
        term.writeln(`\x1b[2m${text}\x1b[0m`);
    },

    /** Write pre-formatted ANSI text as a line. */
    writeRaw(term, ansiText) {
        term.writeln(ansiText);
    },

    clear(term) { term.clear(); },

    destroy(term) {
        if (term._resizeObserver) term._resizeObserver.disconnect();
        term.dispose();
    },
};
