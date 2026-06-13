document.addEventListener('DOMContentLoaded', function () {

    /* ── Network canvas animation ── */
    const canvas = document.getElementById('networkCanvas');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    class Particle {
        constructor() { this.reset(); }
        reset() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.size = Math.random() * 3 + 1;
            this.speedX = Math.random() * 2 - 1;
            this.speedY = Math.random() * 2 - 1;
            this.color = ['rgba(65,100,74,0.7)', 'rgba(233,118,43,0.7)', 'rgba(13,71,21,0.7)', 'rgba(255,255,255,0.5)'][Math.floor(Math.random() * 4)];
        }
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            if (this.x > canvas.width || this.x < 0) this.speedX *= -1;
            if (this.y > canvas.height || this.y < 0) this.speedY *= -1;
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fillStyle = this.color;
            ctx.fill();
        }
    }

    const particles = Array.from({ length: 100 }, () => new Particle());

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        particles.forEach(p => { p.update(); p.draw(); });
        for (let a = 0; a < particles.length; a++) {
            for (let b = a + 1; b < particles.length; b++) {
                const dx = particles[a].x - particles[b].x;
                const dy = particles[a].y - particles[b].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(255,255,255,${(1 - dist / 150) * 0.3})`;
                    ctx.lineWidth = 1;
                    ctx.moveTo(particles[a].x, particles[a].y);
                    ctx.lineTo(particles[b].x, particles[b].y);
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }
    animate();

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        particles.forEach(p => p.reset());
    });

    /* ── Fluent Toast System ── */
    const toastContainer = document.getElementById('fluentToastContainer');

    const TOAST_CONFIG = {
        success: { icon: 'fluent:checkmark-circle-20-filled', title: 'Success' },
        danger:  { icon: 'fluent:dismiss-circle-20-filled',   title: 'Error'   },
        error:   { icon: 'fluent:dismiss-circle-20-filled',   title: 'Error'   },
        warning: { icon: 'fluent:warning-20-filled',          title: 'Warning' },
        info:    { icon: 'fluent:info-20-filled',             title: 'Information' },
    };

    function showFluentToast(message, type) {
        const cfg = TOAST_CONFIG[type] || TOAST_CONFIG.info;
        const cssType = type === 'danger' ? 'error' : type;

        const toast = document.createElement('div');
        toast.className = `fluent-toast toast-${cssType}`;
        toast.innerHTML = `
            <div class="fluent-toast-body">
                <div class="fluent-toast-accent"></div>
                <iconify-icon icon="${cfg.icon}" class="fluent-toast-icon"></iconify-icon>
                <div class="fluent-toast-content">
                    <div class="fluent-toast-title">${cfg.title}</div>
                    <div class="fluent-toast-message">${message}</div>
                </div>
                <button class="fluent-toast-close" aria-label="Dismiss">
                    <iconify-icon icon="fluent:dismiss-20-regular"></iconify-icon>
                </button>
            </div>
            <div class="fluent-toast-progress"><div class="fluent-toast-bar"></div></div>
        `;

        toast.querySelector('.fluent-toast-close').addEventListener('click', () => dismissToast(toast));
        toastContainer.appendChild(toast);
        const timer = setTimeout(() => dismissToast(toast), 5000);
        toast._timer = timer;
    }

    function dismissToast(toast) {
        if (toast._timer) clearTimeout(toast._timer);
        toast.style.animation = 'toastOut 0.22s ease forwards';
        setTimeout(() => toast.remove(), 220);
    }

    /* ── Show server-side flash messages as Fluent toasts ── */
    document.querySelectorAll('#serverMessages span').forEach(el => {
        showFluentToast(el.dataset.msg, el.dataset.type);
    });

    /* ── Password show/hide toggle ── */
    const pwInput = document.getElementById('password');
    const pwToggle = document.getElementById('pwToggle');
    const pwToggleIcon = document.getElementById('pwToggleIcon');

    if (pwToggle) {
        pwToggle.addEventListener('click', () => {
            const isPassword = pwInput.type === 'password';
            pwInput.type = isPassword ? 'text' : 'password';
            pwToggleIcon.setAttribute('icon', isPassword ? 'fluent:eye-off-20-regular' : 'fluent:eye-20-regular');
        });
    }

    /* ── Password requirements ── */
    const pwReqs = document.getElementById('pwRequirements');
    const rules = [
        { id: 'req-len',     test: v => v.length >= 8           },
        { id: 'req-upper',   test: v => /[A-Z]/.test(v)         },
        { id: 'req-lower',   test: v => /[a-z]/.test(v)         },
        { id: 'req-num',     test: v => /[0-9]/.test(v)         },
        { id: 'req-special', test: v => /[^A-Za-z0-9]/.test(v)  },
    ];

    function updateRequirements(value) {
        rules.forEach(rule => {
            const el = document.getElementById(rule.id);
            if (!el) return;
            const met = rule.test(value);
            el.classList.toggle('met', met);
            el.querySelector('iconify-icon').setAttribute(
                'icon', met ? 'fluent:checkmark-circle-20-filled' : 'fluent:circle-20-regular'
            );
        });
    }

    pwInput.addEventListener('focus', () => pwReqs && pwReqs.classList.add('visible'));
    pwInput.addEventListener('blur',  () => { if (pwInput.value === '') pwReqs && pwReqs.classList.remove('visible'); });
    pwInput.addEventListener('input', () => updateRequirements(pwInput.value));

    /* ── Form submit with client-side validation ── */
    const loginForm = document.getElementById('loginForm');

    loginForm.addEventListener('submit', function (e) {
        const password = pwInput.value;
        const failures = rules.filter(r => !r.test(password));

        if (failures.length > 0) {
            e.preventDefault();
            const messages = {
                'req-len':     'Password must be at least 8 characters.',
                'req-upper':   'Password must include at least one uppercase letter.',
                'req-lower':   'Password must include at least one lowercase letter.',
                'req-num':     'Password must include at least one number.',
                'req-special': 'Password must include at least one special character.',
            };
            showFluentToast(messages[failures[0].id], 'danger');
            pwReqs && pwReqs.classList.add('visible');
            return;
        }

        // Valid — let the form POST to Flask naturally
    });
});
