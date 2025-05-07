const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const messageBox = document.getElementById('message');

function showMessage(text, type = 'info') {
    messageBox.textContent = text;
    messageBox.style.color = type === 'error' ? '#c0392b' : '#2c3e50';
}

function clearMessage() {
    messageBox.textContent = '';
}

function validateInputs(username, password) {
    if (!username || !password) {
        showMessage('Please fill in all fields.', 'error');
        return false;
    }
    if (username.length < 3 || password.length < 4) {
        showMessage('Username or password is too short.', 'error');
        return false;
    }
    return true;
}

async function submitForm() {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!validateInputs(username, password)) return;

    showMessage('Please wait...', 'info');

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.message === 'success') {
                showMessage('Login successful! Redirecting...');
                setTimeout(() => {
                    window.location.href = '/';  
                }, 1000);
            } else {
                showMessage(data.message, 'info');
            }
        } else {
            showMessage('Invalid username or password', 'error');
        }
    } catch (err) {
        console.error(err);
        showMessage('Network error. Please try again later.', 'error');
    }
}

