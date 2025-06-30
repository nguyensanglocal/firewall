
function blockIP(ip, alert_type) {
    if (confirm(`Are you sure you want to block IP ${ip}?`)) {
        fetch('/add_blacklist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: `ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent('Blocked from alert: ' + alert_type)}`
        }).then(response => {
            if (response.ok) {
                alert(`IP ${ip} has been blocked.`);
                location.reload();
            } else {
                alert('Failed to block IP.');
            }
        }).catch(() => {
            alert('Error blocking IP.');
        });
    }
}
