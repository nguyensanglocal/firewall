let autoRefreshInterval;
let currentSort = { column: null, direction: null };
let allRows = [];
let filteredRows = [];
let currentPage = 1;
let itemsPerPage = 25;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    allRows = Array.from(document.querySelectorAll('#logsTable tbody tr'));
    filteredRows = [...allRows];
    updatePagination();
});

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

document.getElementById('itemsPerPage').addEventListener('change', function() {
    itemsPerPage = parseInt(this.value);
    currentPage = 1;
    updatePagination();
});

// Sort functionality
document.querySelectorAll('.sortable').forEach(header => {
    header.addEventListener('click', function() {
        const column = this.dataset.column;
        sortTable(column);
    });
});

function sortTable(column) {
    const direction = (currentSort.column === column && currentSort.direction === 'asc') ? 'desc' : 'asc';
    
    // Remove previous sort indicators
    document.querySelectorAll('.sortable').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
    });
    
    // Add new sort indicator
    const header = document.querySelector(`[data-column="${column}"]`);
    header.classList.add(direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
    
    // Sort filtered rows
    filteredRows.sort((a, b) => {
        let aVal, bVal;
        
        switch(column) {
            case 'ip':
                aVal = a.dataset.ip;
                bVal = b.dataset.ip;
                break;
            case 'timestamp':
                aVal = new Date(a.dataset.timestamp);
                bVal = new Date(b.dataset.timestamp);
                break;
            case 'path':
                aVal = a.dataset.path;
                bVal = b.dataset.path;
                break;
            case 'method':
                aVal = a.dataset.method;
                bVal = b.dataset.method;
                break;
            case 'user_agent':
                aVal = a.dataset.userAgent;
                bVal = b.dataset.userAgent;
                break;
            case 'status':
                aVal = parseInt(a.dataset.status);
                bVal = parseInt(b.dataset.status);
                break;
            case 'suspicious':
                aVal = parseInt(a.dataset.suspicious);
                bVal = parseInt(b.dataset.suspicious);
                break;
            case 'threat':
                aVal = parseInt(a.dataset.threat);
                bVal = parseInt(b.dataset.threat);
                break;
            default:
                aVal = a.textContent;
                bVal = b.textContent;
        }
        
        if (aVal < bVal) return direction === 'asc' ? -1 : 1;
        if (aVal > bVal) return direction === 'asc' ? 1 : -1;
        return 0;
    });
    
    currentSort = { column, direction };
    currentPage = 1;
    updatePagination();
}

function filterTable() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const threatFilter = document.getElementById('filterThreat').value;
    const suspiciousFilter = document.getElementById('filterSuspicious').value;
    
    filteredRows = allRows.filter(row => {
        const text = row.textContent.toLowerCase();
        const threat = parseInt(row.dataset.threat);
        const suspicious = row.dataset.suspicious;
        
        // Search filter
        if (searchTerm && !text.includes(searchTerm)) {
            return false;
        }
        
        // Threat filter
        if (threatFilter) {
            if (threatFilter === 'high' && threat < 4) return false;
            if (threatFilter === 'medium' && (threat < 2 || threat >= 4)) return false;
            if (threatFilter === 'low' && threat >= 2) return false;
        }
        
        // Suspicious filter
        if (suspiciousFilter && suspicious !== suspiciousFilter) {
            return false;
        }
        
        return true;
    });
    
    // Re-apply current sort if any
    if (currentSort.column) {
        const column = currentSort.column;
        const direction = currentSort.direction;
        
        filteredRows.sort((a, b) => {
            let aVal, bVal;
            
            switch(column) {
                case 'ip':
                    aVal = a.dataset.ip;
                    bVal = b.dataset.ip;
                    break;
                case 'timestamp':
                    aVal = new Date(a.dataset.timestamp);
                    bVal = new Date(b.dataset.timestamp);
                    break;
                case 'path':
                    aVal = a.dataset.path;
                    bVal = b.dataset.path;
                    break;
                case 'method':
                    aVal = a.dataset.method;
                    bVal = b.dataset.method;
                    break;
                case 'user_agent':
                    aVal = a.dataset.userAgent;
                    bVal = b.dataset.userAgent;
                    break;
                case 'status':
                    aVal = parseInt(a.dataset.status);
                    bVal = parseInt(b.dataset.status);
                    break;
                case 'suspicious':
                    aVal = parseInt(a.dataset.suspicious);
                    bVal = parseInt(b.dataset.suspicious);
                    break;
                case 'threat':
                    aVal = parseInt(a.dataset.threat);
                    bVal = parseInt(b.dataset.threat);
                    break;
                default:
                    aVal = a.textContent;
                    bVal = b.textContent;
            }
            
            if (aVal < bVal) return direction === 'asc' ? -1 : 1;
            if (aVal > bVal) return direction === 'asc' ? 1 : -1;
            return 0;
        });
    }
    
    currentPage = 1;
    updatePagination();
}

function updatePagination() {
    const totalFilteredRows = filteredRows.length;
    const totalPages = Math.ceil(totalFilteredRows / itemsPerPage);
    
    // Hide all rows first
    allRows.forEach(row => {
        row.style.display = 'none';
    });
    
    // Show only rows for current page
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const rowsToShow = filteredRows.slice(startIndex, endIndex);
    
    rowsToShow.forEach(row => {
        row.style.display = '';
    });
    
    // Update records info
    const recordsInfo = document.getElementById('recordsInfo');
    const start = totalFilteredRows === 0 ? 0 : startIndex + 1;
    const end = Math.min(endIndex, totalFilteredRows);
    recordsInfo.innerHTML = `<i class="fas fa-database"></i> Showing ${start} - ${end} of ${totalFilteredRows} logs`;
    
    // Update pagination controls
    updatePaginationControls(totalPages);
}

function updatePaginationControls(totalPages) {
    const paginationContainer = document.getElementById('paginationContainer');
    let paginationHTML = '';
    
    // Previous button
    paginationHTML += `
        <li class="page-item ${currentPage <= 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="changePage(${currentPage - 1})">
                <i class="fas fa-chevron-left"></i> Previous
            </a>
        </li>
    `;
    
    // Page numbers
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, startPage + 4);
    
    for (let i = startPage; i <= endPage; i++) {
        paginationHTML += `
            <li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" onclick="changePage(${i})">${i}</a>
            </li>
        `;
    }
    
    // Next button
    paginationHTML += `
        <li class="page-item ${currentPage >= totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="changePage(${currentPage + 1})">
                Next <i class="fas fa-chevron-right"></i>
            </a>
        </li>
    `;
    
    paginationContainer.innerHTML = paginationHTML;
}

function changePage(page) {
    const totalPages = Math.ceil(filteredRows.length / itemsPerPage);
    if (page >= 1 && page <= totalPages) {
        currentPage = page;
        updatePagination();
    }
}

function clearFilters() {
    document.getElementById('searchInput').value = '';
    document.getElementById('filterThreat').value = '';
    document.getElementById('filterSuspicious').value = '';
    
    // Clear sort
    document.querySelectorAll('.sortable').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
    });
    currentSort = { column: null, direction: null };
    
    filteredRows = [...allRows];
    currentPage = 1;
    updatePagination();
}

// Auto refresh functionality
// document.getElementById('autoRefresh').addEventListener('change', function() {
//     if (this.checked) {
//         autoRefreshInterval = setInterval(() => {
//             location.reload();
//         }, 10000); // Refresh every 10 seconds
//     } else {
//         clearInterval(autoRefreshInterval);
//     }
// });

function exportLogs() {
    // Export only visible/filtered rows
    const csvContent = "data:text/csv;charset=utf-8," + 
        "IP,Timestamp,Path,Method,User Agent,Status,Suspicious,Threat\n" +
        filteredRows.map(row => {
            const cells = Array.from(row.cells);
            return cells.map(cell => '"' + cell.textContent.trim().replace(/"/g, '""') + '"').join(',');
        }).join('\n');
    
    const link = document.createElement('a');
    link.setAttribute('href', encodeURI(csvContent));
    link.setAttribute('download', 'firewall_logs_' + new Date().toISOString().slice(0, 10) + '.csv');
    link.click();
}
