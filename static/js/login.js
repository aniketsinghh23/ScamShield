const form = document.getElementById('loginForm');
const passwordInput = document.getElementById('loginPassword');
const passwordToggle = document.querySelector('.password-toggle');
const status = document.getElementById('loginStatus');
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

passwordToggle?.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    passwordToggle.textContent = isPassword ? 'Hide' : 'Show';
    passwordToggle.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
});

form?.addEventListener('submit', event => {
    event.preventDefault();

    if (!form.checkValidity()) {
        status.textContent = 'Enter a valid email and a password of at least 8 characters.';
        form.reportValidity();
        return;
    }

    status.textContent = 'Signing in...';

    fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            email: document.getElementById('loginEmail').value.trim(),
            password: passwordInput.value,
            remember: document.getElementById('rememberLogin').checked
        })
    })
        .then(async response => {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Unable to sign in.');
            }
            return data;
        })
        .then(() => {
            status.textContent = 'Signed in successfully.';
            window.location.href = '/dashboard';
        })
        .catch(error => {
            status.textContent = error.message;
        });
});
