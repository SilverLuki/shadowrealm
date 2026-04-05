/* ─── Shadow Realm Archive — Main JS ─────────────────────────────────────── */
/* build:2.1.0 min | routes:public=[/,/login,/logout,/profile,/archive,/api/duel,/export/pdf] internal=[/internal/vault] | renderer-api:off | dbg:0 */

// ── Token display on profile page ─────────────────────────────────────────
function displayToken() {
    const box = document.getElementById('tokenBox');
    if (!box) return;

    function getCookie(name) {
        const val = document.cookie.split('; ').find(r => r.startsWith(name + '='));
        return val ? val.split('=').slice(1).join('=') : null;
    }

    const token = getCookie('session_token');
    if (!token) {
        box.textContent = 'No token found.';
        return;
    }
    const parts = token.split('.');
    box.innerHTML = parts.map((p, i) =>
        `<span class="token-section">${p}</span>${i < 2 ? '<span class="token-dot">.</span>' : ''}`
    ).join('');
}

// ── GraphiQL query runner ──────────────────────────────────────────────────
function setQuery(q) {
    const el = document.getElementById('queryInput');
    if (el) el.value = q;
}

async function runQuery() {
    const input = document.getElementById('queryInput');
    const box   = document.getElementById('resultBox');
    if (!input || !box) return;

    const query = input.value.trim();
    if (!query) return;

    box.innerHTML = '<span style="color:var(--text-dim);font-style:italic;">// Querying the Archive...</span>';

    try {
        const res = await fetch('/api/duel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await res.json();
        box.textContent = JSON.stringify(data, null, 2);
    } catch(e) {
        box.innerHTML = `<span style="color:var(--red-bright);">// Error: ${e.message}</span>`;
    }
}

// ── Keyboard shortcut: Ctrl+Enter to run GraphQL query ───────────────────
function initGraphiQL() {
    const input = document.getElementById('queryInput');
    if (!input) return;
    input.addEventListener('keydown', e => {
        if (e.ctrlKey && e.key === 'Enter') runQuery();
    });
}

// ── URL chip click handler ─────────────────────────────────────────────────
function initUrlChips() {
    document.querySelectorAll('.url-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const urlInput = document.querySelector('[name=template_url]');
            if (urlInput) urlInput.value = chip.textContent.trim();
        });
    });
}

// ── Subtle particle effect on hero pages ──────────────────────────────────
function initParticles() {
    const canvas = document.getElementById('particleCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles = Array.from({length: 40}, () => ({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        r: Math.random() * 1.5 + 0.3,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        alpha: Math.random() * 0.5 + 0.1,
    }));

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        particles.forEach(p => {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(201,168,76,${p.alpha})`;
            ctx.fill();
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0) p.x = canvas.width;
            if (p.x > canvas.width)  p.x = 0;
            if (p.y < 0) p.y = canvas.height;
            if (p.y > canvas.height) p.y = 0;
        });
        requestAnimationFrame(draw);
    }
    draw();

    window.addEventListener('resize', () => {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ── Boot ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    displayToken();
    initGraphiQL();
    initUrlChips();
    initParticles();
});
