class SuspiciousIPTable {
    constructor() {
        this.originalData = [];
        this.filteredData = [];
        this.currentPage = 1;
        this.entriesPerPage = 10;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.searchQuery = '';
        this.threatFilter = 'all';
        
        this.init();
    }
    
    init() {
        this.loadOriginalData();
        this.restoreState();
        this.bindEvents();
        this.updateTable();
    }
    
    restoreState() {
        const urlParams = new URLSearchParams(window.location.search);
        
        // Restore search query
        this.searchQuery = urlParams.get('search') || '';
        if (this.searchQuery) {
            document.getElementById('searchInput').value = this.searchQuery;
        }
        
        // Restore entries per page
        this.entriesPerPage = parseInt(urlParams.get('entries')) || 10;
        document.getElementById('entriesPerPage').value = this.entriesPerPage;
        
        // Restore threat filter
        this.threatFilter = urlParams.get('threat') || 'all';
        document.getElementById('threatFilter').value = this.threatFilter;
        
        // Restore sort
        this.sortColumn = urlParams.get('sort') || null;
        this.sortDirection = urlParams.get('dir') || 'asc';
        
        // Restore current page
        this.currentPage = parseInt(urlParams.get('page')) || 1;
        
        // Apply filters
        if (this.searchQuery) {
            this.applySearch();
        }
        if (this.threatFilter !== 'all') {
            this.applyThreatFilter();
        }
        if (this.sortColumn) {
            this.applySort();
            this.updateSortIcons();
        }
    }
    
    saveState() {
        const urlParams = new URLSearchParams();
        
        if (this.searchQuery) urlParams.set('search', this.searchQuery);
        if (this.entriesPerPage !== 10) urlParams.set('entries', this.entriesPerPage);
        if (this.threatFilter !== 'all') urlParams.set('threat', this.threatFilter);
        if (this.sortColumn) {
            urlParams.set('sort', this.sortColumn);
            urlParams.set('dir', this.sortDirection);
        }
        if (this.currentPage !== 1) urlParams.set('page', this.currentPage);
        
        const newUrl = window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
        window.history.replaceState({}, '', newUrl);
    }
    
    loadOriginalData() {
        const rows = document.querySelectorAll('#tableBody tr');
        this.originalData = Array.from(rows).map(row => ({
            ip: row.dataset.ip,
            requests: parseInt(row.dataset.requests),
            threat: parseFloat(row.dataset.threat),
            element: row.cloneNode(true)
        }));
        this.filteredData = [...this.originalData];
    }
    
    bindEvents() {
        // Sort events
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', () => {
                const column = header.dataset.column;
                this.sort(column);
            });
        });
        
        // Search event
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.search(e.target.value);
        });
        
        // Entries per page event
        document.getElementById('entriesPerPage').addEventListener('change', (e) => {
            this.entriesPerPage = parseInt(e.target.value);
            this.currentPage = 1;
            this.updateTable();
            this.saveState();
        });
        
        // Threat filter event
        document.getElementById('threatFilter').addEventListener('change', (e) => {
            this.filterByThreat(e.target.value);
        });
    }
    
    sort(column) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }
        
        this.applySort();
        this.currentPage = 1;
        this.updateSortIcons();
        this.updateTable();
        this.saveState();
    }
    
    applySort() {
        this.filteredData.sort((a, b) => {
            let aVal = a[this.sortColumn];
            let bVal = b[this.sortColumn];
            
            if (this.sortColumn === 'ip') {
                // Enhanced IP sorting
                const aNum = this.ipToNumber(aVal);
                const bNum = this.ipToNumber(bVal);
                
                // Handle BigInt comparison for IPv6
                if (typeof aNum === 'string' && typeof bNum === 'string') {
                    const comparison = BigInt(aNum) < BigInt(bNum) ? -1 : 
                                    BigInt(aNum) > BigInt(bNum) ? 1 : 0;
                    return this.sortDirection === 'asc' ? comparison : -comparison;
                }
                
                // Handle regular number comparison
                if (typeof aNum === 'number' && typeof bNum === 'number') {
                    const comparison = aNum - bNum;
                    return this.sortDirection === 'asc' ? comparison : -comparison;
                }
                
                // Fallback to string comparison
                const comparison = aVal.localeCompare(bVal);
                return this.sortDirection === 'asc' ? comparison : -comparison;
            }
            
            // Regular sorting for other columns
            if (aVal < bVal) return this.sortDirection === 'asc' ? -1 : 1;
            if (aVal > bVal) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
    }
    
    ipToNumber(ip) {
        // Handle IPv4
        if (ip.includes('.') && !ip.includes(':')) {
            return this.ipv4ToNumber(ip);
        }
        // Handle IPv6
        else if (ip.includes(':')) {
            return this.ipv6ToNumber(ip);
        }
        // Fallback for other formats
        else {
            return ip;
        }
    }
    
    ipv4ToNumber(ip) {
        const parts = ip.split('.');
        
        // Validate IPv4 format
        if (parts.length !== 4) {
            return 0;
        }
        
        let result = 0;
        for (let i = 0; i < 4; i++) {
            const octet = parseInt(parts[i]);
            
            // Validate octet range (0-255)
            if (isNaN(octet) || octet < 0 || octet > 255) {
                return 0;
            }
            
            result = (result << 8) + octet;
        }
        
        // Handle negative numbers (JavaScript bitwise operations are signed 32-bit)
        return result >>> 0;
    }
    
    ipv6ToNumber(ip) {
        try {
            // Normalize IPv6 address
            let normalized = this.normalizeIPv6(ip);
            
            // Convert to BigInt for proper comparison
            let result = BigInt(0);
            const parts = normalized.split(':');
            
            for (let i = 0; i < parts.length; i++) {
                const part = parts[i] || '0';
                const value = BigInt(parseInt(part, 16));
                result = (result << BigInt(16)) + value;
            }
            
            // Convert to string for consistent comparison
            return result.toString();
        } catch (e) {
            return ip; // Fallback to string comparison
        }
    }
    
    normalizeIPv6(ip) {
        // Handle IPv4-mapped IPv6 addresses
        if (ip.includes('.')) {
            const parts = ip.split(':');
            const ipv4Part = parts[parts.length - 1];
            if (ipv4Part.includes('.')) {
                const ipv4Parts = ipv4Part.split('.');
                if (ipv4Parts.length === 4) {
                    const hex1 = (parseInt(ipv4Parts[0]) * 256 + parseInt(ipv4Parts[1])).toString(16).padStart(4, '0');
                    const hex2 = (parseInt(ipv4Parts[2]) * 256 + parseInt(ipv4Parts[3])).toString(16).padStart(4, '0');
                    parts[parts.length - 1] = hex1 + ':' + hex2;
                    ip = parts.join(':');
                }
            }
        }
        
        // Expand :: notation
        if (ip.includes('::')) {
            const parts = ip.split('::');
            const leftParts = parts[0] ? parts[0].split(':') : [];
            const rightParts = parts[1] ? parts[1].split(':') : [];
            const missingParts = 8 - leftParts.length - rightParts.length;
            
            const expandedParts = [
                ...leftParts,
                ...Array(missingParts).fill('0'),
                ...rightParts
            ];
            
            ip = expandedParts.join(':');
        }
        
        // Pad each part to 4 digits
        return ip.split(':').map(part => 
            part.padStart(4, '0')
        ).join(':');
    }
    
    search(query) {
        this.searchQuery = query;
        this.applySearch();
        this.currentPage = 1;
        this.updateTable();
        this.saveState();
    }
    
    applySearch() {
        if (!this.searchQuery.trim()) {
            this.filteredData = [...this.originalData];
        } else {
            const searchTerm = this.searchQuery.toLowerCase();
            this.filteredData = this.originalData.filter(item => 
                item.ip.toLowerCase().includes(searchTerm)
            );
        }
        
        // Re-apply threat filter if active
        if (this.threatFilter !== 'all') {
            this.applyThreatFilter();
        }
    }
    
    filterByThreat(level) {
        this.threatFilter = level;
        this.applyThreatFilter();
        this.currentPage = 1;
        this.updateTable();
        this.saveState();
    }
    
    applyThreatFilter() {
        let baseData = this.originalData;
        
        // Apply search filter first if active
        if (this.searchQuery.trim()) {
            const searchTerm = this.searchQuery.toLowerCase();
            baseData = baseData.filter(item => 
                item.ip.toLowerCase().includes(searchTerm)
            );
        }
        
        // Then apply threat filter
        if (this.threatFilter === 'all') {
            this.filteredData = [...baseData];
        } else {
            this.filteredData = baseData.filter(item => {
                switch(this.threatFilter) {
                    case 'high': return item.threat >= 4.0;
                    case 'medium': return item.threat >= 2.0 && item.threat < 4.0;
                    case 'low': return item.threat < 2.0;
                    default: return true;
                }
            });
        }
    }
    
    updateSortIcons() {
        document.querySelectorAll('.sortable').forEach(header => {
            header.classList.remove('asc', 'desc');
            if (header.dataset.column === this.sortColumn) {
                header.classList.add(this.sortDirection);
            }
        });
    }
    
    updateTable() {
        const start = (this.currentPage - 1) * this.entriesPerPage;
        const end = start + this.entriesPerPage;
        const pageData = this.filteredData.slice(start, end);
        
        const tbody = document.getElementById('tableBody');
        tbody.innerHTML = '';
        
        pageData.forEach(item => {
            tbody.appendChild(item.element.cloneNode(true));
        });
        
        this.updatePagination();
        this.updateInfo();
    }
    
    updatePagination() {
        const totalPages = Math.ceil(this.filteredData.length / this.entriesPerPage);
        const pagination = document.getElementById('pagination');
        
        pagination.innerHTML = '';
        
        if (totalPages <= 1) return;
        
        // Previous button
        const prevLi = document.createElement('li');
        prevLi.className = `page-item ${this.currentPage === 1 ? 'disabled' : ''}`;
        prevLi.innerHTML = '<a class="page-link" href="#" data-page="prev">Previous</a>';
        pagination.appendChild(prevLi);
        
        // Page numbers
        const startPage = Math.max(1, Math.min(this.currentPage - 2, totalPages - 4));
        const endPage = Math.min(totalPages, startPage + 4);
        
        if (startPage > 1) {
            const firstLi = document.createElement('li');
            firstLi.className = 'page-item';
            firstLi.innerHTML = '<a class="page-link" href="#" data-page="1">1</a>';
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
            li.className = `page-item ${i === this.currentPage ? 'active' : ''}`;
            li.innerHTML = `<a class="page-link" href="#" data-page="${i}">${i}</a>`;
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
            lastLi.innerHTML = `<a class="page-link" href="#" data-page="${totalPages}">${totalPages}</a>`;
            pagination.appendChild(lastLi);
        }
        
        // Next button
        const nextLi = document.createElement('li');
        nextLi.className = `page-item ${this.currentPage === totalPages ? 'disabled' : ''}`;
        nextLi.innerHTML = '<a class="page-link" href="#" data-page="next">Next</a>';
        pagination.appendChild(nextLi);
        
        // Bind pagination events
        pagination.addEventListener('click', (e) => {
            e.preventDefault();
            if (e.target.classList.contains('page-link')) {
                const page = e.target.dataset.page;
                if (page === 'prev' && this.currentPage > 1) {
                    this.currentPage--;
                } else if (page === 'next' && this.currentPage < totalPages) {
                    this.currentPage++;
                } else if (!isNaN(page)) {
                    this.currentPage = parseInt(page);
                }
                this.updateTable();
                this.saveState();
            }
        });
    }
    
    updateInfo() {
        const start = Math.min((this.currentPage - 1) * this.entriesPerPage + 1, this.filteredData.length);
        const end = Math.min(this.currentPage * this.entriesPerPage, this.filteredData.length);
        
        document.getElementById('showingStart').textContent = this.filteredData.length > 0 ? start : 0;
        document.getElementById('showingEnd').textContent = end;
        document.getElementById('totalEntries').textContent = this.filteredData.length;
    }
}

// Initialize table functionality
let suspiciousTable;
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('tableBody')) {
        suspiciousTable = new SuspiciousIPTable();
    }
});

function refreshData() {
    // Save current state to URL before refresh
    if (suspiciousTable) {
        suspiciousTable.saveState();
    }
    location.reload();
}

// Auto refresh every 30 seconds
setInterval(refreshData, 30000);