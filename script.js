// Login form handler
document.addEventListener('DOMContentLoaded', function () {
	const loginForm = document.getElementById('loginForm');
	if (loginForm) {
		loginForm.addEventListener('submit', async function (e) {
			e.preventDefault();
			const email = document.getElementById('loginEmail').value;
			const password = document.getElementById('loginPassword').value;

			try {
				const response = await fetch('/login', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({ email, password })
				});
				const data = await response.json();
				if (response.ok) {
					// Save sessionId in localStorage for later use
					localStorage.setItem('sessionId', data.sessionId);
					// Redirect based on role
					if (data.role === 'admin') {
						window.location.href = '/admin.html';
					} else {
						window.location.href = '/student.html';
					}
				} else {
					showError(data.message || 'An unexpected error occurred. Please try again.');
				}
			} catch (err) {
				showError('An unexpected error occurred. Please try again.');
			}
		});
	}

	// Show error message function
	function showError(message) {
		let errorDiv = document.getElementById('loginError');
		if (!errorDiv) {
			errorDiv = document.createElement('div');
			errorDiv.id = 'loginError';
			errorDiv.className = 'mt-4 text-center text-red-600 font-medium';
			loginForm.parentNode.insertBefore(errorDiv, loginForm.nextSibling);
		}
		errorDiv.textContent = message;
	}
});
