function handleLogout(event) {
    event.preventDefault();
    fetch('/logout')
        .then(response => response.json())
        .then(data => {
            if (data.message === 'success') {
                // Reload the current page
                window.location.reload();  
            }
        })
        .catch(error => console.error('Error:', error));
}

function handleLogout(event) {
    event.preventDefault();
    fetch('/logout')
        .then(response => response.json())
        .then(data => {
            if (data.message === 'success') {
                // Reload the current page
                window.location.reload();  
            }
        })
        .catch(error => console.error('Error:', error));
}