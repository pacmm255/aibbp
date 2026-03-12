/**
 * Login page.
 */
const LoginPage = {
    mount(container) {
        container.innerHTML = `
            <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;margin:-24px -32px;">
                <div class="card" style="width:380px;padding:40px;">
                    <div style="text-align:center;margin-bottom:32px;">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" style="margin-bottom:12px;">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        <h1 style="font-size:1.5rem;color:var(--text);margin:0;">AIBBP</h1>
                        <p style="color:var(--text-muted);font-size:0.85rem;margin-top:4px;">Security Dashboard</p>
                    </div>
                    <form id="login-form">
                        <div style="margin-bottom:16px;">
                            <label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Email</label>
                            <input type="email" id="login-email" placeholder="admin@aibbp.local"
                                style="width:100%;padding:10px 12px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.9rem;outline:none;box-sizing:border-box;"
                                required>
                        </div>
                        <div style="margin-bottom:24px;">
                            <label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Password</label>
                            <input type="password" id="login-password" placeholder="Password"
                                style="width:100%;padding:10px 12px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.9rem;outline:none;box-sizing:border-box;"
                                required>
                        </div>
                        <div id="login-error" style="color:var(--danger);font-size:0.85rem;margin-bottom:12px;display:none;"></div>
                        <button type="submit" class="btn btn-primary" id="login-btn" style="width:100%;padding:10px;font-size:0.95rem;">
                            Sign In
                        </button>
                    </form>
                </div>
            </div>
        `;

        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('login-btn');
            const errEl = document.getElementById('login-error');
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;

            btn.disabled = true;
            btn.textContent = 'Signing in...';
            errEl.style.display = 'none';

            try {
                const data = await API.post('/api/auth/login', { email, password });
                API.setToken(data.token);
                localStorage.setItem('aibbp_user', JSON.stringify(data.user));
                WS.connect(data.token);
                window.location.hash = '#/dashboard';
            } catch (err) {
                errEl.textContent = err.message || 'Login failed';
                errEl.style.display = 'block';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Sign In';
            }
        });
    },

    unmount() {},
};
