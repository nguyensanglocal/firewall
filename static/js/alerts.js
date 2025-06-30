// Pagination and sorting variables
let currentPage = 1;
let itemsPerPage = 10;
let currentSort = 'timestamp-desc';
let allRows = [];
let filteredRows = [];

// Save and restore state
function saveState() {
    const state = {
        currentPage,
        itemsPerPage,
        currentSort,
        searchTerm: document.getElementById('searchAlerts').value,
        severityFilter: document.getElementById('filterSeverity').value,
        statusFilter: document.getElementById('filterStatus').value
    };
    sessionStorage.setItem('alertsState', JSON.stringify(state));
}

function restoreState() {
    const saved = sessionStorage.getItem('alertsState');
    if (saved) {
        const state = JSON.parse(saved);
        currentPage = state.currentPage || 1;
        itemsPerPage = state.itemsPerPage || 10;
        currentSort = state.currentSort || 'timestamp-desc';

        // Restore form values
        document.getElementById('searchAlerts').value = state.searchTerm || '';
        document.getElementById('filterSeverity').value = state.severityFilter || '';
        document.getElementById('filterStatus').value = state.statusFilter || '';
        document.getElementById('itemsPerPage').value = itemsPerPage;
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function () {
    allRows = Array.from(document.querySelectorAll('.alert-row'));

    // Restore previous state
    restoreState();

    applyFiltersAndSort();

    // Event listeners
    document.getElementById('searchAlerts').addEventListener('input', function () {
        applyFiltersAndSort();
        saveState();
    });
    document.getElementById('filterSeverity').addEventListener('change', function () {
        applyFiltersAndSort();
        saveState();
    });
    document.getElementById('filterStatus').addEventListener('change', function () {
        applyFiltersAndSort();
        saveState();
    });
    document.getElementById('itemsPerPage').addEventListener('change', function () {
        itemsPerPage = parseInt(this.value);
        currentPage = 1;
        updatePagination();
        saveState();
    });

    // Sortable column headers
    document.querySelectorAll('.sortable').forEach(header => {
        header.style.cursor = 'pointer';
        header.addEventListener('click', function () {
            const sortField = this.dataset.sort;
            const currentSortField = currentSort.split('-')[0];
            const currentDirection = currentSort.split('-')[1];

            if (currentSortField === sortField) {
                currentSort = sortField + '-' + (currentDirection === 'asc' ? 'desc' : 'asc');
            } else {
                currentSort = sortField + '-desc';
            }

            applyFiltersAndSort();
            updateSortIcons();
            saveState();
        });
    });

    updateSortIcons();
});

function applyFiltersAndSort() {
    // Apply filters
    filteredRows = filterRows();

    // Apply sorting
    sortRows();

    // Reset to first page
    currentPage = 1;

    // Update display
    updatePagination();
    updateTotalCount();
}

function filterRows() {
    const searchTerm = document.getElementById('searchAlerts').value.toLowerCase();
    const severityFilter = document.getElementById('filterSeverity').value;
    const statusFilter = document.getElementById('filterStatus').value;

    return allRows.filter(row => {
        const text = row.textContent.toLowerCase();
        const severity = row.dataset.severity;
        const resolved = row.dataset.resolved;

        let show = true;

        if (searchTerm && !text.includes(searchTerm)) {
            show = false;
        }

        if (severityFilter) {
            if (severityFilter === '3' && parseInt(severity) < 3) {
                show = false;
            } else if (severityFilter !== '3' && severity !== severityFilter) {
                show = false;
            }
        }

        if (statusFilter && resolved !== statusFilter) {
            show = false;
        }

        return show;
    });
}

function sortRows() {
    const [field, direction] = currentSort.split('-');

    filteredRows.sort((a, b) => {
        let aVal, bVal;

        switch (field) {
            case 'severity':
                aVal = parseInt(a.dataset.severity);
                bVal = parseInt(b.dataset.severity);
                break;
            case 'ip':
                aVal = a.dataset.ip;
                bVal = b.dataset.ip;
                break;
            case 'type':
                aVal = a.dataset.type;
                bVal = b.dataset.type;
                break;
            case 'timestamp':
                aVal = new Date(a.dataset.timestamp);
                bVal = new Date(b.dataset.timestamp);
                break;
            case 'status':
                aVal = parseInt(a.dataset.resolved);
                bVal = parseInt(b.dataset.resolved);
                break;
            default:
                return 0;
        }

        if (aVal < bVal) return direction === 'asc' ? -1 : 1;
        if (aVal > bVal) return direction === 'asc' ? 1 : -1;
        return 0;
    });
}

function updatePagination() {
    const totalItems = filteredRows.length;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, totalItems);

    // Hide all rows first
    allRows.forEach(row => row.style.display = 'none');

    // Show current page rows
    for (let i = startIndex; i < endIndex; i++) {
        if (filteredRows[i]) {
            filteredRows[i].style.display = '';
        }
    }

    // Update showing info
    document.getElementById('showingStart').textContent = totalItems > 0 ? startIndex + 1 : 0;
    document.getElementById('showingEnd').textContent = endIndex;
    document.getElementById('showingTotal').textContent = totalItems;

    // Generate pagination controls
    generatePaginationControls(totalPages);
}

function generatePaginationControls(totalPages) {
    const pagination = document.getElementById('pagination');
    pagination.innerHTML = '';

    if (totalPages <= 1) return;

    // Previous button
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
    prevLi.innerHTML = `<a class="page-link" href="#"  onclick="changePage(${currentPage - 1})">
        <i class="fas fa-chevron-left"></i> Previous
    </a>`;
    pagination.appendChild(prevLi);

    // Page numbers
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        const firstLi = document.createElement('li');
        firstLi.className = 'page-item';
        firstLi.innerHTML = `<a class="page-link" href="#" onclick="changePage(1)">1</a>`;
        pagination.appendChild(firstLi);

        if (startPage > 2) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = 'page-item disabled';
            ellipsisLi.innerHTML = '<span class="page-link">...</span>';
            pagination.appendChild(ellipsisLi);
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        const li = document.createElement('li');
        li.className = `page-item ${i === currentPage ? 'active' : ''}`;
        li.innerHTML = `<a class="page-link" href="#" onclick="changePage(${i})">${i}</a>`;
        pagination.appendChild(li);
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = 'page-item disabled';
            ellipsisLi.innerHTML = '<span class="page-link">...</span>';
            pagination.appendChild(ellipsisLi);
        }

        const lastLi = document.createElement('li');
        lastLi.className = 'page-item';
        lastLi.innerHTML = `<a class="page-link" href="#" onclick="changePage(${totalPages})">${totalPages}</a>`;
        pagination.appendChild(lastLi);
    }

    // Next button
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
    nextLi.innerHTML = `<a class="page-link" href="#" onclick="changePage(${currentPage + 1})">Next
        <i class="fas fa-chevron-right"></i>
    </a>`;
    pagination.appendChild(nextLi);
}

function changePage(page) {
    const totalPages = Math.ceil(filteredRows.length / itemsPerPage);
    if (page >= 1 && page <= totalPages) {
        currentPage = page;
        updatePagination();
    }
}

function updateTotalCount() {
    document.getElementById('totalCount').textContent = filteredRows.length;
}

function updateSortIcons() {
    document.querySelectorAll('.sort-icon').forEach(icon => {
        icon.className = 'fas fa-sort ms-1 sort-icon';
    });

    const [field, direction] = currentSort.split('-');
    const activeHeader = document.querySelector(`[data-sort="${field}"] .sort-icon`);
    if (activeHeader) {
        activeHeader.className = `fas fa-sort-${direction === 'asc' ? 'up' : 'down'} ms-1 sort-icon`;
    }
}

// Original functions
function resolveAllAlerts() {
    if (confirm('Are you sure you want to resolve all active alerts?')) {
        alert('Feature not implemented in demo. Would resolve all alerts.');
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

// Auto refresh every 15 seconds (commented out for demo)
// setInterval(() => {
//     location.reload();
// }, 15000);