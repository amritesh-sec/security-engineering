const nav = document.getElementById('siteNav');
if (nav) window.addEventListener('scroll', () => nav.classList.toggle('scrolled', window.scrollY > 20));
const t = document.getElementById('navToggle'), l = document.getElementById('navLinks');
if (t && l) t.addEventListener('click', () => l.classList.toggle('open'));
const cards = document.querySelectorAll('.tool-card');
if (cards.length) {
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((e, i) => {
      if (e.isIntersecting) {
        e.target.style.animationDelay = (i * 0.05) + 's';
        e.target.style.animation = 'fadeUp 0.5s ease both';
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.1 });
  cards.forEach(c => obs.observe(c));
}
