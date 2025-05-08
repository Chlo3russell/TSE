function startAttack(type) {
    // Start the traffic monitor before the attack
    fetch('/start-monitoring', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            console.log('Traffic monitor started:', data.message || data);
        })
        .catch(error => {
            console.error('Error starting traffic monitor:', error);
        });

    document.getElementById(`${type}Btn`).disabled = true;
    document.getElementById(`${type}StopBtn`).style.display = 'inline-block';
    document.getElementById(`${type}Status`).textContent = 'Attack running...';

    fetch(`/${type}_attack`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (!data.success) {
                document.getElementById(`${type}Status`).textContent = 'Attack failed to start';
                resetButtons(type);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById(`${type}Status`).textContent = 'Error starting attack';
            resetButtons(type);
        });
}

function stopAttack(type) {
    fetch(`/stop_${type}_attack`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            document.getElementById(`${type}Status`).textContent = 'Attack stopped';
            resetButtons(type);
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById(`${type}Status`).textContent = 'Error stopping attack';
        });
}

function resetButtons(type) {
    document.getElementById(`${type}Btn`).disabled = false;
    document.getElementById(`${type}StopBtn`).style.display = 'none';
}

