document.addEventListener('DOMContentLoaded', function () {

    /* ── Black particle network animation ── */
    const canvas = document.getElementById('networkCanvas');
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', () => { resize(); particles.forEach(p => p.reset()); });

    class Particle {
        constructor() { this.reset(); }
        reset() {
            this.x      = Math.random() * canvas.width;
            this.y      = Math.random() * canvas.height;
            this.size   = Math.random() * 2.5 + 1;
            this.speedX = (Math.random() - 0.5) * 1.2;
            this.speedY = (Math.random() - 0.5) * 1.2;
        }
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            if (this.x > canvas.width  || this.x < 0) this.speedX *= -1;
            if (this.y > canvas.height || this.y < 0) this.speedY *= -1;
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 0, 0, 0.55)';
            ctx.fill();
        }
    }

    const particles = Array.from({ length: 110 }, () => new Particle());

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        for (let a = 0; a < particles.length; a++) {
            particles[a].update();
            particles[a].draw();

            for (let b = a + 1; b < particles.length; b++) {
                const dx   = particles[a].x - particles[b].x;
                const dy   = particles[a].y - particles[b].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 140) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, 0, 0, ${(1 - dist / 140) * 0.3})`;
                    ctx.lineWidth   = 0.8;
                    ctx.moveTo(particles[a].x, particles[a].y);
                    ctx.lineTo(particles[b].x, particles[b].y);
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }
    animate();

    /* ── Form submission — let POST reach Flask ── */
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function (e) {
            // Allow normal POST; Flask handles validation
        });
    }
});
