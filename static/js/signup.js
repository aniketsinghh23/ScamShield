const form = document.getElementById('signupForm');
const passwordInput = document.getElementById('signupPassword');
const passwordToggle = document.querySelector('.password-toggle');
const status = document.getElementById('signupStatus');
const emailInput = document.getElementById('signupEmail');
const nameInput = document.getElementById('signupName');
const termsInput = document.getElementById('signupTerms');
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
        status.textContent = 'Complete your name, email, password, and terms agreement.';
        form.reportValidity();
        return;
    }

    status.textContent = 'Creating your account...';

    fetch('/api/auth/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            name: nameInput.value.trim(),
            email: emailInput.value.trim(),
            password: passwordInput.value,
            termsAccepted: termsInput.checked
        })
    })
        .then(async response => {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Unable to create your account.');
            }
            return data;
        })
        .then(() => {
            status.textContent = 'Account created successfully.';
            window.location.href = '/dashboard';
        })
        .catch(error => {
            status.textContent = error.message;
        });
});
