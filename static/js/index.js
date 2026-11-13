const menuButton = document.querySelector('.menu-toggle');
const navigation = document.querySelector('.navigation');

menuButton?.addEventListener('click', () => {
    const isOpen = navigation.classList.toggle('is-open');
    menuButton.setAttribute('aria-expanded', String(isOpen));
});

navigation?.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
        navigation.classList.remove('is-open');
        menuButton.setAttribute('aria-expanded', 'false');
    });
});

const brand = document.querySelector('.brand');
const brandName = document.querySelector('.brand-name');
const scrambleCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
let scrambleTimer;

brand?.addEventListener('mouseenter', () => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        return;
    }

    const target = brandName.dataset.value;
    let iteration = 0;
    clearInterval(scrambleTimer);

    scrambleTimer = setInterval(() => {
        brandName.textContent = target
            .split('')
            .map((character, index) => {
                if (character === ' ' || index < iteration) {
                    return character;
                }

                return scrambleCharacters[Math.floor(Math.random() * scrambleCharacters.length)];
            })
            .join('');

        iteration += 1 / 2;
        if (iteration >= target.length) {
            clearInterval(scrambleTimer);
            brandName.textContent = target;
        }
    }, 45);
});

const revealElements = document.querySelectorAll(
    '.hero-copy, .feature-panel, .story-section, .story-card, .service-item, .idea-section, .feedback-form'
);
const heroActions = document.querySelector('.hero-actions');
const navAuth = document.querySelector('.nav-auth');

if ('IntersectionObserver' in window && heroActions && navAuth) {
    const authVisibilityObserver = new IntersectionObserver(([entry]) => {
        navAuth.classList.toggle('is-visible', !entry.isIntersecting);
    }, { threshold: 0.15 });
    authVisibilityObserver.observe(heroActions);

    const revealObserver = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                revealObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12 });

    revealElements.forEach((element, index) => {
        element.classList.add('reveal');
        element.style.transitionDelay = `${Math.min(index * 45, 240)}ms`;
        revealObserver.observe(element);
    });
} else {
    revealElements.forEach(element => element.classList.add('is-visible'));
}

document.getElementById('feedbackForm')?.addEventListener('submit', event => {
    event.preventDefault();
    const email = document.getElementById('feedbackEmail').value.trim();
    const message = document.getElementById('feedbackMessage').value.trim();
    const subject = encodeURIComponent('ScamShield-AI feedback');
    const body = encodeURIComponent(`From: ${email}\n\n${message}`);

    window.location.href = `mailto:scamshieldai@gmail.com?subject=${subject}&body=${body}`;
    document.getElementById('feedbackStatus').textContent =
        'Your email app is opening with the feedback ready to send.';
});
