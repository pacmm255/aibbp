/**
 * ApexCharts dark theme wrappers.
 */
const Charts = {
    _defaultOptions() {
        return {
            chart: {
                background: 'transparent',
                foreColor: '#6b7280',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace',
                toolbar: { show: false },
                animations: { enabled: true, speed: 500 },
            },
            theme: { mode: 'dark' },
            grid: {
                borderColor: '#1e2d3d',
                strokeDashArray: 3,
            },
            tooltip: {
                theme: 'dark',
                style: { fontSize: '12px' },
            },
            colors: ['#3b82f6', '#22c55e', '#eab308', '#ef4444', '#06b6d4', '#a855f7', '#f97316'],
        };
    },

    area(container, options) {
        const opts = {
            ...this._defaultOptions(),
            ...options,
            chart: { ...this._defaultOptions().chart, type: 'area', height: 250, ...(options.chart || {}) },
            stroke: { curve: 'smooth', width: 2, ...(options.stroke || {}) },
            fill: {
                type: 'gradient',
                gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0.05, stops: [0, 90, 100] },
                ...(options.fill || {}),
            },
            dataLabels: { enabled: false },
        };
        const chart = new ApexCharts(container, opts);
        chart.render();
        return chart;
    },

    donut(container, options) {
        const opts = {
            ...this._defaultOptions(),
            ...options,
            chart: { ...this._defaultOptions().chart, type: 'donut', height: 250, ...(options.chart || {}) },
            plotOptions: {
                pie: {
                    donut: {
                        size: '70%',
                        labels: {
                            show: true,
                            name: { color: '#c9d1d9' },
                            value: { color: '#c9d1d9', fontSize: '1.2rem' },
                            total: { show: true, color: '#6b7280', label: 'Total' },
                        },
                    },
                },
                ...(options.plotOptions || {}),
            },
            legend: { position: 'bottom', labels: { colors: '#6b7280' } },
            dataLabels: { enabled: false },
        };
        const chart = new ApexCharts(container, opts);
        chart.render();
        return chart;
    },

    bar(container, options) {
        const opts = {
            ...this._defaultOptions(),
            ...options,
            chart: { ...this._defaultOptions().chart, type: 'bar', height: 250, ...(options.chart || {}) },
            plotOptions: {
                bar: { horizontal: true, borderRadius: 4, barHeight: '60%' },
                ...(options.plotOptions || {}),
            },
            dataLabels: { enabled: false },
        };
        const chart = new ApexCharts(container, opts);
        chart.render();
        return chart;
    },

    treemap(container, options) {
        const opts = {
            ...this._defaultOptions(),
            ...options,
            chart: { ...this._defaultOptions().chart, type: 'treemap', height: 250, ...(options.chart || {}) },
            dataLabels: { enabled: true, style: { fontSize: '12px' } },
        };
        const chart = new ApexCharts(container, opts);
        chart.render();
        return chart;
    },
};
