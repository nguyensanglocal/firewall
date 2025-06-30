
# Template HTML files sẽ được tạo riêng
templates = {
    'base.html': '''
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Firewall Monitor{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .threat-high { color: #dc3545; font-weight: bold; }
        .threat-medium { color: #fd7e14; font-weight: bold; }
        .threat-low { color: #28a745; }
        .suspicious { background-color: #fff3cd; }
        .navbar-brand { font-weight: bold; }
        .card { border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .table-hover tbody tr:hover { background-color: #f8f9fa; }
        .alert-animate { animation: pulse 2s infinite; }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
        }
        .status-online { background-color: #28a745; }
        .status-warning { background-color: #ffc107; }
        .status-danger { background-color: #dc3545; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt"></i> Firewall Monitor
                <span class="status-indicator status-online"></span>
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                <a class="nav-link" href="/suspicious"><i class="fas fa-list"></i> Suspicious (24h)</a>
                <a class="nav-link" href="/logs"><i class="fas fa-list"></i> Requests (24h)</a>
                <a class="nav-link" href="/blacklist"><i class="fas fa-ban"></i> Blacklist</a>
                <a class="nav-link" href="/alerts"><i class="fas fa-exclamation-triangle"></i> Alerts</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
    ''',
    
    'dashboard.html': '''
{% extends "base.html" %}
{% block title %}Dashboard - Firewall Monitor{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-tachometer-alt"></i> Security Dashboard</h2>
    <div>
        <button class="btn btn-outline-primary" onclick="refreshData()">
            <i class="fas fa-sync-alt"></i> Refresh
        </button>
        <span class="badge bg-success ms-2">Online</span>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <a href="/logs" class="text-decoration-none text-white">
            <div class="card bg-primary text-white">
                <div class="card-body text-center">
                    <i class="fas fa-globe fa-2x mb-2"></i>
                    <h5>Requests (24h)</h5>
                    <h2>{{ total_requests_24h }}</h2>
                    <small>Total incoming requests</small>
                </div>
            </div>
        </a>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <a href="/suspicious" class="text-decoration-none text-white">
            <div class="card-body text-center">
                <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                <h5>Suspicious (24h)</h5>
                <h2>{{ suspicious_requests_24h }}</h2>
                <small>Potentially malicious</small>
            </div>
            </a>
        </div>
    </div>
    <div class="col-md-3">
       <a href="/blacklist" class="text-decoration-none text-white">
            <div class="card bg-danger text-white">
                <div class="card-body text-center">
                    <i class="fas fa-ban fa-2x mb-2"></i>
                    <h5>Blacklisted IPs</h5>
                    <h2>{{ total_blacklisted }}</h2>
                    <small>Blocked addresses</small>
                </div>
            </div>
        </a>
    </div>
    <div class="col-md-3">
        <a href="/alerts" class="text-decoration-none text-white">
            <div class="card bg-info text-white">
                <div class="card-body text-center">
                    <i class="fas fa-bell fa-2x mb-2"></i>
                    <h5>Active Alerts</h5>
                    <h2>{{ active_alerts }}</h2>
                    <small>Needs attention</small>
                </div>
            </div>
        </a>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-gradient">
                <a href="/suspicious" class="text-decoration-none text-dark">
                <h5><i class="fas fa-user-secret"></i> Top Suspicious IPs (24h)</h5>
                </a>
            </div>
            <div class="card-body">
                {% if top_suspicious_ips %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th><i class="fas fa-network-wired"></i> IP Address</th>
                                <th><i class="fas fa-chart-bar"></i> Requests</th>
                                <th><i class="fas fa-thermometer-half"></i> Avg Threat</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip, count, avg_threat in top_suspicious_ips %}
                            <tr>
                                <td>
                                    <code>{{ ip }}</code>
                                </td>
                                <td>
                                    <span class="badge bg-secondary">{{ count }}</span>
                                </td>
                                <td>
                                    <span class="{% if avg_threat >= 4 %}threat-high{% elif avg_threat >= 2 %}threat-medium{% else %}threat-low{% endif %}">
                                        <i class="fas fa-{% if avg_threat >= 4 %}fire{% elif avg_threat >= 2 %}exclamation{% else %}check{% endif %}"></i>
                                        {{ "%.1f"|format(avg_threat) }}
                                    </span>
                                </td>
                                <td>
                                    <a href="/block_blacklist/{{ ip }}" class="btn btn-sm btn-outline-danger">
                                        <i class="fas fa-ban"></i> Block
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center text-muted py-4">
                    <i class="fas fa-shield-alt fa-3x mb-3"></i>
                    <p>No suspicious activity detected</p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card">
            <a href="/alerts" class="text-decoration-none text-dark">
            <div class="card-header bg-gradient">
                <h5><i class="fas fa-exclamation-circle"></i> Recent Alerts</h5>
            </div>
            </a>
            <div class="card-body">
                {% if recent_alerts %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Type</th>
                                <th>Time</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip, alert_type, message, severity, timestamp in recent_alerts %}
                            <tr class="{% if severity >= 3 %}alert-animate{% endif %}">
                                <td><code>{{ ip }}</code></td>
                                <td>
                                    <span class="badge {% if alert_type == 'HIGH_THREAT' %}bg-danger{% elif alert_type == 'RATE_LIMIT' %}bg-warning{% else %}bg-info{% endif %}">
                                        {{ alert_type }}
                                    </span>
                                </td>
                                <td><small>{{ timestamp }}</small></td>
                                <td>
                                    <span class="badge {% if severity >= 3 %}bg-danger{% elif severity >= 2 %}bg-warning{% else %}bg-info{% endif %}">
                                        {% for i in range(severity) %}<i class="fas fa-star"></i>{% endfor %}
                                    </span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center text-muted py-4">
                    <i class="fas fa-check-circle fa-3x mb-3"></i>
                    <p>No active alerts</p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-chart-line"></i> Request Activity (Last 24 Hours)</h5>
            </div>
            <div class="card-body">
                <canvas id="activityChart" height="100"></canvas>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
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
</script>
{% endblock %}
    ''',
    
    'logs.html': '''
{% extends "base.html" %}
{% block title %}Access Logs - Firewall Monitor{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-list"></i> Access Logs</h2>
    <div>
        <button class="btn btn-outline-secondary" onclick="exportLogs()">
            <i class="fas fa-download"></i> Export
        </button>
        <button class="btn btn-outline-primary" onclick="location.reload()">
            <i class="fas fa-sync-alt"></i> Refresh
        </button>
    </div>
</div>

<div class="row mb-3">
    <div class="col-md-6">
        <div class="input-group">
            <span class="input-group-text"><i class="fas fa-search"></i></span>
            <input type="text" class="form-control" id="searchInput" placeholder="Search by IP, path, or user agent...">
        </div>
    </div>
    <div class="col-md-3">
        <select class="form-select" id="filterThreat">
            <option value="">All Threat Levels</option>
            <option value="high">High Threat (4+)</option>
            <option value="medium">Medium Threat (2-3)</option>
            <option value="low">Low Threat (0-1)</option>
        </select>
    </div>
    <div class="col-md-3">
        <select class="form-select" id="filterSuspicious">
            <option value="">All Requests</option>
            <option value="1">Suspicious Only</option>
            <option value="0">Normal Only</option>
        </select>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div class="d-flex justify-content-between align-items-center">
            <span>
                <i class="fas fa-database"></i> 
                Showing {{ ((page-1) * per_page + 1) if logs else 0 }} - {{ (page * per_page) if (page * per_page) < total_logs else total_logs }} of {{ total_logs }} logs
            </span>
            <div class="btn-group btn-group-sm">
                <input type="checkbox" class="btn-check" id="autoRefresh" autocomplete="off">
                <label class="btn btn-outline-primary" for="autoRefresh">Auto Refresh</label>
            </div>
        </div>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0" id="logsTable">
                <thead class="table-dark">
                    <tr>
                        <th><i class="fas fa-network-wired"></i> IP Address</th>
                        <th><i class="fas fa-clock"></i> Timestamp</th>
                        <th><i class="fas fa-route"></i> Path</th>
                        <th><i class="fas fa-method"></i> Method</th>
                        <th><i class="fas fa-user-agent"></i> User Agent</th>
                        <th><i class="fas fa-code"></i> Status</th>
                        <th><i class="fas fa-shield-alt"></i> Suspicious</th>
                        <th><i class="fas fa-thermometer-half"></i> Threat</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip, timestamp, path, method, user_agent, status_code, is_suspicious, threat_level in logs %}
                    <tr class="{% if is_suspicious %}suspicious{% endif %}" data-threat="{{ threat_level }}" data-suspicious="{{ is_suspicious }}">
                        <td>
                            <code class="{% if threat_level >= 4 %}text-danger{% elif threat_level >= 2 %}text-warning{% endif %}">
                                {{ ip }}
                            </code>
                        </td>
                        <td>
                            <small>{{ timestamp }}</small>
                        </td>
                        <td>
                            <code>{{ path }}</code>
                        </td>
                        <td>
                            <span class="badge {% if method == 'POST' %}bg-primary{% elif method == 'GET' %}bg-success{% elif method == 'DELETE' %}bg-danger{% else %}bg-secondary{% endif %}">
                                {{ method }}
                            </span>
                        </td>
                        <td>
                            <small class="text-muted" title="{{ user_agent }}">
                                {{ user_agent[:50] }}{% if user_agent|length > 50 %}...{% endif %}
                            </small>
                        </td>
                        <td>
                            <span class="badge {% if status_code < 300 %}bg-success{% elif status_code < 400 %}bg-info{% elif status_code < 500 %}bg-warning{% else %}bg-danger{% endif %}">
                                {{ status_code }}
                            </span>
                        </td>
                        <td class="text-center">
                            {% if is_suspicious %}
                                <i class="fas fa-exclamation-triangle text-warning" title="Suspicious request"></i>
                            {% else %}
                                <i class="fas fa-check-circle text-success" title="Normal request"></i>
                            {% endif %}
                        </td>
                        <td>
                            <div class="d-flex align-items-center">
                                <div class="progress" style="width: 60px; height: 10px;">
                                    <div class="progress-bar {% if threat_level >= 4 %}bg-danger{% elif threat_level >= 2 %}bg-warning{% else %}bg-success{% endif %}" 
                                         style="width: {{ (threat_level / 5 * 100) }}%"></div>
                                </div>
                                <span class="ms-2 small">{{ threat_level }}</span>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Pagination -->
<nav aria-label="Logs pagination" class="mt-4">
    <ul class="pagination justify-content-center">
        <li class="page-item {% if page <= 1 %}disabled{% endif %}">
            <a class="page-link" href="?page={{ page - 1 if page > 1 else 1 }}">
                <i class="fas fa-chevron-left"></i> Previous
            </a>
        </li>
        
        {% set start_page = (page - 2) if (page - 2) > 0 else 1 %}
        {% set end_page = start_page + 4 %}
        {% set total_pages = (total_logs / per_page) | round(0, 'ceil') | int %}
        {% if end_page > total_pages %}{% set end_page = total_pages %}{% endif %}
        
        {% for p in range(start_page, end_page + 1) %}
            <li class="page-item {% if p == page %}active{% endif %}">
                <a class="page-link" href="?page={{ p }}">{{ p }}</a>
            </li>
        {% endfor %}
        
        <li class="page-item {% if page >= total_pages %}disabled{% endif %}">
            <a class="page-link" href="?page={{ page + 1 if page < total_pages else page }}">
                Next <i class="fas fa-chevron-right"></i>
            </a>
        </li>
    </ul>
</nav>
{% endblock %}

{% block scripts %}
<script>
let autoRefreshInterval;

// Search functionality
document.getElementById('searchInput').addEventListener('input', function() {
    filterTable();
});

document.getElementById('filterThreat').addEventListener('change', function() {
    filterTable();
});

document.getElementById('filterSuspicious').addEventListener('change', function() {
    filterTable();
});

function filterTable() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const threatFilter = document.getElementById('filterThreat').value;
    const suspiciousFilter = document.getElementById('filterSuspicious').value;
    const rows = document.querySelectorAll('#logsTable tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const threat = parseInt(row.dataset.threat);
        const suspicious = row.dataset.suspicious;
        
        let show = true;
        
        // Search filter
        if (searchTerm && !text.includes(searchTerm)) {
            show = false;
        }
        
        // Threat filter
        if (threatFilter) {
            if (threatFilter === 'high' && threat < 4) show = false;
            if (threatFilter === 'medium' && (threat < 2 || threat >= 4)) show = false;
            if (threatFilter === 'low' && threat >= 2) show = false;
        }
        
        // Suspicious filter
        if (suspiciousFilter && suspicious !== suspiciousFilter) {
            show = false;
        }
        
        row.style.display = show ? '' : 'none';
    });
}

// Auto refresh functionality
document.getElementById('autoRefresh').addEventListener('change', function() {
    if (this.checked) {
        autoRefreshInterval = setInterval(() => {
            location.reload();
        }, 10000); // Refresh every 10 seconds
    } else {
        clearInterval(autoRefreshInterval);
    }
});

function exportLogs() {
    // Simple CSV export
    const rows = Array.from(document.querySelectorAll('#logsTable tbody tr'));
    const csvContent = "data:text/csv;charset=utf-8," + 
        "IP,Timestamp,Path,Method,User Agent,Status,Suspicious,Threat\\n" +
        rows.map(row => {
            const cells = Array.from(row.cells);
            return cells.map(cell => '"' + cell.textContent.trim().replace(/"/g, '""') + '"').join(',');
        }).join('\\n');
    
    const link = document.createElement('a');
    link.setAttribute('href', encodeURI(csvContent));
    link.setAttribute('download', 'firewall_logs_' + new Date().toISOString().slice(0, 10) + '.csv');
    link.click();
}
</script>
{% endblock %}
    ''',
    
    'blacklist.html': '''
{% extends "base.html" %}
{% block title %}IP Blacklist - Firewall Monitor{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-ban"></i> IP Blacklist Management</h2>
    <button class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#addBlacklistModal">
        <i class="fas fa-plus"></i> Add IP to Blacklist
    </button>
</div>

<div class="row mb-4">
    <div class="col-md-4">
        <div class="card bg-danger text-white">
            <div class="card-body text-center">
                <i class="fas fa-ban fa-2x mb-2"></i>
                <h5>Total Blacklisted</h5>
                <h2>{{ blacklist_entries|length }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card bg-warning text-white">
            <div class="card-body text-center">
                <i class="fas fa-clock fa-2x mb-2"></i>
                <h5>Added Today</h5>
                <h2>{{ blacklist_entries|selectattr('2', 'match', '.*' + today + '.*')|list|length if today is defined else 0 }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card bg-info text-white">
            <div class="card-body text-center">
                <i class="fas fa-shield-alt fa-2x mb-2"></i>
                <h5>Protection Level</h5>
                <h2>HIGH</h2>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div class="d-flex justify-content-between align-items-center">
            <h5><i class="fas fa-list"></i> Blacklisted IP Addresses</h5>
            <div class="input-group" style="width: 300px;">
                <span class="input-group-text"><i class="fas fa-search"></i></span>
                <input type="text" class="form-control" id="searchBlacklist" placeholder="Search IP addresses...">
            </div>
        </div>
    </div>
    <div class="card-body p-0">
        {% if blacklist_entries %}
        <div class="table-responsive">
            <table class="table table-hover mb-0" id="blacklistTable">
                <thead class="table-dark">
                    <tr>
                        <th><i class="fas fa-network-wired"></i> IP Address</th>
                        <th><i class="fas fa-comment"></i> Reason</th>
                        <th><i class="fas fa-calendar"></i> Added Date</th>
                        <th><i class="fas fa-toggle-on"></i> Status</th>
                        <th><i class="fas fa-cogs"></i> Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip_address, reason, added_date, is_active in blacklist_entries %}
                    <tr class="{% if not is_active %}table-secondary{% endif %}">
                        <td>
                            <code class="{% if is_active %}text-danger{% else %}text-muted{% endif %}">
                                {{ ip_address }}
                            </code>
                        </td>
                        <td>
                            <span class="badge bg-secondary">{{ reason }}</span>
                        </td>
                        <td>
                            <small>{{ added_date }}</small>
                        </td>
                        <td>
                            {% if is_active %}
                                <span class="badge bg-danger">
                                    <i class="fas fa-ban"></i> Active
                                </span>
                            {% else %}
                                <span class="badge bg-secondary">
                                    <i class="fas fa-pause"></i> Inactive
                                </span>
                            {% endif %}
                        </td>
                        <td>
                            {% if is_active %}
                                <a href="/remove_blacklist/{{ ip_address }}" class="btn btn-sm btn-outline-success" 
                                   onclick="return confirm('Are you sure you want to remove {{ ip_address }} from blacklist?')">
                                    <i class="fas fa-check"></i> Unblock
                                </a>
                            {% else %}
                                <a href="/block_blacklist/{{ ip_address }}" class="btn btn-sm btn-outline-danger" 
                                   onclick="return confirm('Are you sure you want to remove {{ ip_address }} from blacklist?')">
                                    <i class="fas fa-check"></i> Block
                                </a>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="text-center py-5">
            <i class="fas fa-shield-alt fa-4x text-success mb-3"></i>
            <h4>No IP addresses in blacklist</h4>
            <p class="text-muted">Your system is currently not blocking any IP addresses.</p>
        </div>
        {% endif %}
    </div>
</div>

<!-- Add Blacklist Modal -->
<div class="modal fade" id="addBlacklistModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-ban"></i> Add IP to Blacklist
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="/add_blacklist">
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="ip" class="form-label">IP Address *</label>
                        <input type="text" class="form-control" id="ip" name="ip" required 
                               placeholder="e.g., 192.168.1.100" pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$">
                        <div class="form-text">Enter a valid IPv4 address</div>
                    </div>
                    <div class="mb-3">
                        <label for="reason" class="form-label">Reason</label>
                        <select class="form-select" id="reasonSelect" onchange="toggleCustomReason()">
                            <option value="Suspicious activity">Suspicious activity</option>
                            <option value="Rate limit exceeded">Rate limit exceeded</option>
                            <option value="Malicious requests">Malicious requests</option>
                            <option value="Spam/Bot activity">Spam/Bot activity</option>
                            <option value="Security threat">Security threat</option>
                            <option value="custom">Custom reason...</option>
                        </select>
                        <input type="text" class="form-control mt-2" id="customReason" name="reason" 
                               style="display: none;" placeholder="Enter custom reason">
                    </div>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>Warning:</strong> This IP will be immediately blocked from accessing your system.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">
                        <i class="fas fa-ban"></i> Add to Blacklist
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// Search functionality
document.getElementById('searchBlacklist').addEventListener('input', function() {
    const searchTerm = this.value.toLowerCase();
    const rows = document.querySelectorAll('#blacklistTable tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
});

function toggleCustomReason() {
    const select = document.getElementById('reasonSelect');
    const customInput = document.getElementById('customReason');
    
    if (select.value === 'custom') {
        customInput.style.display = 'block';
        customInput.required = true;
        customInput.focus();
    } else {
        customInput.style.display = 'none';
        customInput.required = false;
        customInput.value = select.value;
    }
}

// Initialize reason input
document.getElementById('reasonSelect').addEventListener('change', function() {
    if (this.value !== 'custom') {
        document.getElementById('customReason').value = this.value;
    }
});

// Set initial value
document.getElementById('customReason').value = document.getElementById('reasonSelect').value;
</script>
{% endblock %}
    ''',
    
    'alerts.html': '''
{% extends "base.html" %}
{% block title %}Security Alerts - Firewall Monitor{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-exclamation-triangle"></i> Security Alerts</h2>
    <div>
        <button class="btn btn-outline-success" onclick="resolveAllAlerts()">
            <i class="fas fa-check-double"></i> Resolve All
        </button>
        <button class="btn btn-outline-primary" onclick="location.reload()">
            <i class="fas fa-sync-alt"></i> Refresh
        </button>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-danger text-white">
            <div class="card-body text-center">
                <i class="fas fa-fire fa-2x mb-2"></i>
                <h5>Critical Alerts</h5>
                <h2>{{ alerts|selectattr('4', '>=', 3)|list|length }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body text-center">
                <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                <h5>Warning Alerts</h5>
                <h2>{{ alerts|selectattr('4', '==', 2)|list|length }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body text-center">
                <i class="fas fa-info-circle fa-2x mb-2"></i>
                <h5>Info Alerts</h5>
                <h2>{{ alerts|selectattr('4', '==', 1)|list|length }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body text-center">
                <i class="fas fa-check-circle fa-2x mb-2"></i>
                <h5>Resolved</h5>
                <h2>{{ alerts|selectattr('6', '==', 1)|list|length }}</h2>
            </div>
        </div>
    </div>
</div>

<div class="row mb-3">
    <div class="col-md-6">
        <div class="input-group">
            <span class="input-group-text"><i class="fas fa-search"></i></span>
            <input type="text" class="form-control" id="searchAlerts" placeholder="Search alerts by IP or message...">
        </div>
    </div>
    <div class="col-md-3">
        <select class="form-select" id="filterSeverity">
            <option value="">All Severities</option>
            <option value="3">Critical (3+)</option>
            <option value="2">Warning (2)</option>
            <option value="1">Info (1)</option>
        </select>
    </div>
    <div class="col-md-3">
        <select class="form-select" id="filterStatus">
            <option value="">All Status</option>
            <option value="0">Active</option>
            <option value="1">Resolved</option>
        </select>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <h5><i class="fas fa-bell"></i> Alert History</h5>
    </div>
    <div class="card-body p-0">
        {% if alerts %}
        <div class="table-responsive">
            <table class="table table-hover mb-0" id="alertsTable">
                <thead class="table-dark">
                    <tr>
                        <th><i class="fas fa-exclamation-circle"></i> Severity</th>
                        <th><i class="fas fa-network-wired"></i> IP Address</th>
                        <th><i class="fas fa-tag"></i> Alert Type</th>
                        <th><i class="fas fa-comment"></i> Message</th>
                        <th><i class="fas fa-clock"></i> Timestamp</th>
                        <th><i class="fas fa-toggle-on"></i> Status</th>
                        <th><i class="fas fa-cogs"></i> Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for id, ip_address, alert_type, message, severity, timestamp, is_resolved in alerts %}
                    <tr class="{% if severity >= 3 and not is_resolved %}table-danger{% elif severity >= 2 and not is_resolved %}table-warning{% elif is_resolved %}table-light{% endif %}"
                        data-severity="{{ severity }}" data-resolved="{{ is_resolved }}">
                        <td class="text-center">
                            <div class="d-flex align-items-center">
                                {% if severity >= 3 %}
                                    <i class="fas fa-fire text-danger me-2"></i>
                                    <span class="badge bg-danger">CRITICAL</span>
                                {% elif severity >= 2 %}
                                    <i class="fas fa-exclamation-triangle text-warning me-2"></i>
                                    <span class="badge bg-warning">WARNING</span>
                                {% else %}
                                    <i class="fas fa-info-circle text-info me-2"></i>
                                    <span class="badge bg-info">INFO</span>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <code class="{% if severity >= 3 %}text-danger{% elif severity >= 2 %}text-warning{% endif %}">
                                {{ ip_address }}
                            </code>
                        </td>
                        <td>
                            <span class="badge {% if alert_type == 'HIGH_THREAT' %}bg-danger{% elif alert_type == 'RATE_LIMIT' %}bg-warning{% elif alert_type == 'BLOCKED' %}bg-dark{% else %}bg-secondary{% endif %}">
                                {{ alert_type }}
                            </span>
                        </td>
                        <td>
                            <small>{{ message }}</small>
                        </td>
                        <td>
                            <small>{{ timestamp }}</small>
                        </td>
                        <td>
                            {% if is_resolved %}
                                <span class="badge bg-success">
                                    <i class="fas fa-check"></i> Resolved
                                </span>
                            {% else %}
                                <span class="badge bg-danger">
                                    <i class="fas fa-exclamation"></i> Active
                                </span>
                            {% endif %}
                        </td>
                        <td>
                            {% if not is_resolved %}
                                <div class="btn-group btn-group-sm">
                                    <a href="/resolve_alert/{{ id }}" class="btn btn-outline-success" title="Resolve Alert">
                                        <i class="fas fa-check"></i>
                                    </a>
                                    <button class="btn btn-outline-danger" onclick="blockIP('{{ ip_address }}', '{{ alert_type }}')" title="Block IP">
                                        <i class="fas fa-ban"></i>
                                    </button>
                                    <button class="btn btn-outline-info" onclick="showAlertDetails({{ id }}, '{{ ip_address }}', '{{ alert_type }}', '{{ message }}', '{{ timestamp }}')" title="View Details">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            {% else %}
                                <span class="text-muted small">No actions</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="text-center py-5">
            <i class="fas fa-shield-alt fa-4x text-success mb-3"></i>
            <h4>No security alerts</h4>
            <p class="text-muted">Your system is secure with no active alerts.</p>
        </div>
        {% endif %}
    </div>
</div>

<!-- Alert Details Modal -->
<div class="modal fade" id="alertDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-exclamation-circle"></i> Alert Details
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6">
                        <strong>IP Address:</strong>
                        <p><code id="modalIP"></code></p>
                    </div>
                    <div class="col-md-6">
                        <strong>Alert Type:</strong>
                        <p><span id="modalType" class="badge"></span></p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <strong>Message:</strong>
                        <p id="modalMessage"></p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <strong>Timestamp:</strong>
                        <p id="modalTimestamp"></p>
                    </div>
                    <div class="col-md-6">
                        <strong>Recommended Actions:</strong>
                        <ul id="modalActions">
                        </ul>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-danger" id="modalBlockBtn">
                    <i class="fas fa-ban"></i> Block IP
                </button>
                <button type="button" class="btn btn-success" id="modalResolveBtn">
                    <i class="fas fa-check"></i> Resolve Alert
                </button>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
filterAlerts();

// Search functionality
document.getElementById('searchAlerts').addEventListener('input', function() {
    filterAlerts();
});

document.getElementById('filterSeverity').addEventListener('change', function() {
    filterAlerts();
});

document.getElementById('filterStatus').addEventListener('change', function() {
    filterAlerts();
});

function filterAlerts() {
    const searchTerm = document.getElementById('searchAlerts').value.toLowerCase();
    const severityFilter = document.getElementById('filterSeverity').value;
    const statusFilter = document.getElementById('filterStatus').value;
    const rows = document.querySelectorAll('#alertsTable tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const severity = row.dataset.severity;
        const resolved = row.dataset.resolved;
        
        let show = true;
        
        if (searchTerm && !text.includes(searchTerm)) {
            show = false;
        }
        
        if (severityFilter && severity !== severityFilter) {
            show = false;
        }
        
        if (statusFilter && resolved !== statusFilter) {
            show = false;
        }
        
        row.style.display = show ? '' : 'none';
    });
}

function resolveAllAlerts() {
    if (confirm('Are you sure you want to resolve all active alerts?')) {
        // In a real implementation, this would make an API call
        alert('Feature not implemented in demo. Would resolve all alerts.');
    }
}

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
        return;
    }
}
function showAlertDetails(id, ip, type, message, timestamp) {
    document.getElementById('modalIP').textContent = ip;
    document.getElementById('modalType').textContent = type;
    document.getElementById('modalMessage').textContent = message;
    document.getElementById('modalTimestamp').textContent = timestamp;
    
    // Set badge color based on type
    const typeBadge = document.getElementById('modalType');
    typeBadge.className = 'badge ';
    if (type === 'HIGH_THREAT') {
        typeBadge.className += 'bg-danger';
    } else if (type === 'RATE_LIMIT') {
        typeBadge.className += 'bg-warning';
    } else if (type === 'BLOCKED') {
        typeBadge.className += 'bg-dark';
    } else {
        typeBadge.className += 'bg-secondary';
    }
    
    // Set recommended actions
    const actionsList = document.getElementById('modalActions');
    actionsList.innerHTML = '';
    
    const actions = [];
    if (type === 'HIGH_THREAT') {
        actions.push('Block the IP address immediately');
        actions.push('Investigate the request patterns');
        actions.push('Check server logs for more details');
    } else if (type === 'RATE_LIMIT') {
        actions.push('Consider temporary IP blocking');
        actions.push('Monitor for continued abuse');
        actions.push('Adjust rate limiting thresholds if needed');
    } else if (type === 'BLOCKED') {
        actions.push('Verify the block was effective');
        actions.push('Monitor for attempts from related IPs');
    }
    
    actions.forEach(action => {
        const li = document.createElement('li');
        li.textContent = action;
        actionsList.appendChild(li);
    });
    
    // Set button actions
    document.getElementById('modalBlockBtn').onclick = () => blockIP(ip, '');
    document.getElementById('modalResolveBtn').onclick = () => {
        window.location.href = `/resolve_alert/${id}`;
    };
    
    new bootstrap.Modal(document.getElementById('alertDetailsModal')).show();
}

// Auto refresh every 15 seconds
setInterval(() => {
    location.reload();
}, 15000);
</script>
{% endblock %}
    ''',

    'suspicious.html': '''
{% extends "base.html" %}
{% block title %}Suspicious IPs (24h) - Firewall Monitor{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-exclamation-triangle"></i> Suspicious IPs (24h)</h2>
    <div>
        <button class="btn btn-outline-primary" onclick="refreshData()">
            <i class="fas fa-sync-alt"></i> Refresh
        </button>
    </div>
</div>


<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-body">
                {% if top_suspicious_ips %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th><i class="fas fa-network-wired"></i> IP Address</th>
                                <th><i class="fas fa-chart-bar"></i> Requests</th>
                                <th><i class="fas fa-thermometer-half"></i> Avg Threat</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip, count, avg_threat in top_suspicious_ips %}
                            <tr>
                                <td>
                                    <code>{{ ip }}</code>
                                </td>
                                <td>
                                    <span class="badge bg-secondary">{{ count }}</span>
                                </td>
                                <td>
                                    <span class="{% if avg_threat >= 4 %}threat-high{% elif avg_threat >= 2 %}threat-medium{% else %}threat-low{% endif %}">
                                        <i class="fas fa-{% if avg_threat >= 4 %}fire{% elif avg_threat >= 2 %}exclamation{% else %}check{% endif %}"></i>
                                        {{ "%.1f"|format(avg_threat) }}
                                    </span>
                                </td>
                                <td>
                                    <a href="/block_blacklist/{{ ip }}" class="btn btn-sm btn-outline-danger">
                                        <i class="fas fa-ban"></i> Block
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center text-muted py-4">
                    <i class="fas fa-shield-alt fa-3x mb-3"></i>
                    <p>No suspicious activity detected</p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
    
</div>


{% endblock %}

{% block scripts %}
<script>
function refreshData() {
    location.reload();
}

// Auto refresh every 30 seconds
setInterval(refreshData, 30000);

</script>
{% endblock %}
    '''
    }

def create_templates():
    # Tạo thư mục templates nếu chưa có
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Ghi các template files
    for filename, content in templates.items():
        with open(f'templates/{filename}', 'w', encoding='utf-8') as f:
            f.write(content)
    
if __name__ == '__main__':
    create_templates()
    print("Templates created successfully in the 'templates' directory.")