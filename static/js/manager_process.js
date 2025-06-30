const socket = io();
var monitoringActive = false;

// Sorting state for each table
var sortStates = {};

socket.on('connect', function () {
    console.log('Connected to server');
});

socket.on('connection_update', function (data) {
    if (document.getElementById('connections').classList.contains('active')) {
        displayConnections(data.connections);
    }
});

function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all nav tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(tabName).classList.add('active');
    event.target.classList.add('active');

    // Load data for the active tab
    if (tabName === 'processes') {
        refreshProcesses();
    } else if (tabName === 'connections') {
        refreshConnections();
    } else if (tabName === 'rules') {
        refreshRules();
    }
}

function sortTable(tableId, columnIndex) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const headers = table.querySelectorAll('th');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Skip if table is loading or empty
    if (rows.length === 0 || rows[0].cells.length === 1) return;

    // Initialize sort state for this table if not exists
    if (!sortStates[tableId]) {
        sortStates[tableId] = { column: -1, direction: 'none' };
    }

    let sortDirection = 'asc';

    // Determine sort direction
    if (sortStates[tableId].column === columnIndex) {
        if (sortStates[tableId].direction === 'asc') {
            sortDirection = 'desc';
        } else if (sortStates[tableId].direction === 'desc') {
            sortDirection = 'asc';
        }
    }

    // Clear all header sort classes
    headers.forEach(header => {
        header.classList.remove('sort-asc', 'sort-desc');
    });

    // Add sort class to current header
    headers[columnIndex].classList.add(sortDirection === 'asc' ? 'sort-asc' : 'sort-desc');

    // Sort rows
    rows.sort((a, b) => {
        let aVal = a.cells[columnIndex].textContent.trim();
        let bVal = b.cells[columnIndex].textContent.trim();

        // Handle numeric columns (PID, Connections)
        if (columnIndex === 1 || columnIndex === 3) {
            aVal = parseInt(aVal) || 0;
            bVal = parseInt(bVal) || 0;
        } else {
            // For text columns, convert to lowercase for case-insensitive sorting
            aVal = aVal.toLowerCase();
            bVal = bVal.toLowerCase();
        }

        let comparison = 0;
        if (aVal > bVal) {
            comparison = 1;
        } else if (aVal < bVal) {
            comparison = -1;
        }

        return sortDirection === 'desc' ? -comparison : comparison;
    });

    // Clear tbody and append sorted rows
    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));

    // Update sort state
    sortStates[tableId] = { column: columnIndex, direction: sortDirection };
}

function refreshProcesses() {
    fetch('/firewall/processes')
        .then(response => response.json())
        .then(data => displayProcesses(data))
        .catch(error => showNotification('Error loading processes: ' + error, 'error'));
}

function refreshConnections() {
    fetch('/firewall/connections')
        .then(response => response.json())
        .then(data => displayConnections(data))
        .catch(error => showNotification('Error loading connections: ' + error, 'error'));
}

function refreshRules() {
    fetch('/firewall/rules')
        .then(response => response.json())
        .then(data => displayRules(data))
        .catch(error => showNotification('Error loading rules: ' + error, 'error'));
}

function displayProcesses(processes) {
    const tbody = document.getElementById('processes-table');
    if (processes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No processes with network activity found</td></tr>';
        return;
    }

    tbody.innerHTML = processes.map(proc => `
            <tr>
                <td><strong>${proc.name}</strong></td>
                <td>${proc.pid}</td>
                <td title="${proc.exe}">${proc.exe.length > 50 ? proc.exe.substring(0, 50) + '...' : proc.exe}</td>
                <td>${proc.connections}</td>
                <td><span class="status-badge status-${proc.status}">${proc.status}</span></td>
                <td class="action-buttons">
                    ${proc.status === 'blocked' ?
            `<button class="btn btn-success btn-sm" onclick="allowApp('${proc.exe}')">✅ Allow</button>` :
            `<button class="btn btn-danger btn-sm" onclick="blockApp('${proc.exe}')">🚫 Block</button>`
        }
                </td>
            </tr>
        `).join('');
}

function displayConnections(connections) {
    const tbody = document.getElementById('connections-table');
    if (connections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No active connections found</td></tr>';
        return;
    }

    tbody.innerHTML = connections.map(conn => `
            <tr>
                <td><strong>${conn.process}</strong></td>
                <td>${conn.pid}</td>
                <td>${conn.local_addr}</td>
                <td>${conn.remote_addr}</td>
                <td>${conn.protocol}</td>
                <td><span class="status-badge status-connected">${conn.status}</span></td>
            </tr>
        `).join('');
}

function displayRules(rules) {
    const tbody = document.getElementById('rules-table');
    const allRules = [
        ...rules.blocked_apps.map(app => ({ app, type: 'blocked' })),
        ...rules.allowed_apps.map(app => ({ app, type: 'allowed' }))
    ];

    if (allRules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="loading">No firewall rules configured</td></tr>';
        return;
    }

    tbody.innerHTML = allRules.map(rule => `
            <tr>
                <td title="${rule.app}">${rule.app.length > 60 ? rule.app.substring(0, 60) + '...' : rule.app}</td>
                <td><span class="status-badge status-${rule.type}">${rule.type}</span></td>
                <td class="action-buttons">
                    ${rule.type === 'blocked' ?
            `<button class="btn btn-success btn-sm" onclick="allowApp('${rule.app}')">✅ Allow</button>` :
            `<button class="btn btn-danger btn-sm" onclick="blockApp('${rule.app}')">🚫 Block</button>`
        }
                </td>
            </tr>
        `).join('');
}

function blockApp(appPath) {
    console.log(`Blocking application: ${appPath}`);
    fetch('/firewall/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_path: appPath })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                refreshProcesses();
                refreshRules();
            } else {
                showNotification(data.error, 'error');
            }
        })
        .catch(error => showNotification('Error: ' + error, 'error'));
}

function allowApp(appPath) {
    fetch('/firewall/allow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_path: appPath })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                refreshProcesses();
                refreshRules();
            } else {
                showNotification(data.error, 'error');
            }
        })
        .catch(error => showNotification('Error: ' + error, 'error'));
}

function startMonitoring() {
    fetch('/firewall/monitoring/start', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                monitoringActive = true;
                showNotification(data.message, 'success');
            }
        })
        .catch(error => showNotification('Error: ' + error, 'error'));
}

function stopMonitoring() {
    fetch('/firewall/monitoring/stop', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                monitoringActive = false;
                showNotification(data.message, 'success');
            }
        })
        .catch(error => showNotification('Error: ' + error, 'error'));
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => document.body.removeChild(notification), 300);
    }, 3000);
}

// Load initial data
refreshProcesses();