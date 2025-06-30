
function refreshData() {
    location.reload();
}

// Auto refresh every 30 seconds
setInterval(refreshData, 30000);

// Activity Chart
fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        const ctx = document.getElementById('activityChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: Object.keys(data.hourly_stats || {}),
                datasets: [{
                    label: 'Requests per Hour',
                    data: Object.values(data.hourly_stats || {}),
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    });
