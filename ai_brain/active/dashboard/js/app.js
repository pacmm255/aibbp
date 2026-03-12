/**
 * AIBBP Dashboard — SPA Router & App Shell
 */
const App = {
    _currentPage: null,
    _currentPageName: null,

    _routes: {
        '/login': { page: LoginPage, auth: false },
        '/dashboard': { page: DashboardPage, auth: true },
        '/vulnerabilities': { page: VulnerabilitiesPage, auth: true },
        '/scans': { page: ScansPage, auth: true },
        '/proxy': { page: ProxyPage, auth: true },
    },

    init() {
        // Listen for hash changes
        window.addEventListener('hashchange', () => this._route());

        // Sidebar toggle
        const toggleBtn = document.getElementById('sidebar-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                document.getElementById('sidebar').classList.toggle('collapsed');
            });
        }

        // Responsive: auto-collapse on small screens
        if (window.innerWidth < 768) {
            const sidebar = document.getElementById('sidebar');
            if (sidebar) sidebar.classList.add('collapsed');
        }

        // Logout
        document.getElementById('logout-btn')?.addEventListener('click', () => {
            API.clearToken();
            localStorage.removeItem('aibbp_user');
            WS.disconnect();
            window.location.hash = '#/login';
        });

        // Initialize Lucide icons
        if (window.lucide) {
            window.lucide.createIcons();
        }

        // Load user info
        this._loadUserInfo();

        // Connect WebSocket if token exists
        const token = API.getToken();
        if (token) {
            WS.connect(token);
        }

        // Initial route
        this._route();
    },

    _loadUserInfo() {
        try {
            const user = JSON.parse(localStorage.getItem('aibbp_user') || 'null');
            if (user && user.email) {
                const el = document.getElementById('user-email');
                if (el) el.textContent = user.email;
            }
        } catch (e) {}
    },

    _route() {
        const hash = window.location.hash || '#/dashboard';
        let path = hash.replace('#', '');
        let params = {};

        // Parse parameterized routes: /scans/:id, /vulnerabilities/:id
        const scanMatch = path.match(/^\/scans\/(.+)$/);
        const vulnMatch = path.match(/^\/vulnerabilities\/(.+)$/);
        if (scanMatch) {
            params = { id: scanMatch[1] };
            path = '/scans';
        } else if (vulnMatch) {
            params = { id: vulnMatch[1] };
            path = '/vulnerabilities';
        }

        const route = this._routes[path];
        if (!route) {
            window.location.hash = '#/dashboard';
            return;
        }

        // Auth guard
        const token = API.getToken();
        if (route.auth && !token) {
            window.location.hash = '#/login';
            return;
        }
        if (path === '/login' && token) {
            window.location.hash = '#/dashboard';
            return;
        }

        // Toggle sidebar/main visibility on login page
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.getElementById('main-content');
        if (path === '/login') {
            if (sidebar) sidebar.style.display = 'none';
            if (mainContent) mainContent.style.margin = '0';
        } else {
            if (sidebar) sidebar.style.display = '';
            if (mainContent) mainContent.style.margin = '';
        }

        // Unmount current page
        if (this._currentPage && this._currentPage.unmount) {
            try { this._currentPage.unmount(); } catch (e) { console.error('Unmount error:', e); }
        }

        // Update sidebar active state
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.page === path.replace('/', '')) {
                item.classList.add('active');
            }
        });

        // Mount new page
        const container = document.getElementById('page-container');
        if (container) {
            container.innerHTML = '';
            container.className = 'fade-in';
            this._currentPage = route.page;
            this._currentPageName = path;
            Promise.resolve(route.page.mount(container, params)).catch(e => {
                console.error('Mount error:', e);
                container.innerHTML = `<div class="empty-state"><p>Error loading page: ${e.message}</p></div>`;
            });
        }
    },
};

// Boot the app once when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => App.init());
} else {
    App.init();
}
