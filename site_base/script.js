const menu = document.querySelector('.menu-toggle');
const links = document.querySelector('.nav-links');

menu?.addEventListener('click', () => {
  const open = menu.classList.toggle('open');
  menu.setAttribute('aria-expanded', open);
});

links?.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
  menu?.classList.remove('open');
  menu?.setAttribute('aria-expanded', 'false');
}));

const observer = new IntersectionObserver((entries, obs) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      obs.unobserve(entry.target);
    }
  });
}, { threshold: 0.12 });

document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

const counterObserver = new IntersectionObserver((entries, obs) => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    const el = entry.target;
    const target = Number(el.dataset.counter);
    const suffix = target === 24 ? "" : "";
    let current = 0;
    const duration = 900;
    const start = performance.now();

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(target * eased) + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
    obs.unobserve(el);
  });
}, { threshold: 0.7 });

document.querySelectorAll('[data-counter]').forEach(el => counterObserver.observe(el));
