document.addEventListener('DOMContentLoaded', function () {
    let pendingEntries = [];

    function toggleInputType(type) {
        document.getElementById('singleIpInput').style.display = (type === 'single') ? 'block' : 'none';
        document.getElementById('rangeIpInput').style.display = (type === 'range') ? 'block' : 'none';
    }

    function toggleCustomReason() {
        const reason = document.getElementById('reasonSelect');
        const custom = document.getElementById('customReason');
        custom.style.display = (reason.value === 'custom') ? 'block' : 'none';
    }

    function showAlert(message) {
        const box = document.getElementById('alertBox');
        const msg = document.getElementById('alertMessage');
        msg.textContent = message;
        box.classList.remove('d-none');
        box.classList.add('show');
    }

    function hideAlert() {
        const box = document.getElementById('alertBox');
        box.classList.remove('show');
        box.classList.add('d-none');
    }

    function markInvalid(inputId) {
        document.getElementById(inputId).classList.add('is-invalid');
    }

    function clearValidation() {
        ['ip', 'start_ip', 'end_ip'].forEach(id => {
            document.getElementById(id).classList.remove('is-invalid');
        });
    }

    //   function ipToNumber(ip) {
    //     const parts = ip.split('.').map(Number);
    //     if (parts.length !== 4 || parts.some(p => p < 0 || p > 255)) return null;
    //     return parts[0]*256**3 + parts[1]*256**2 + parts[2]*256 + parts[3];
    //   }
    function ipToNumber(ip) {
        if (ip.includes('.')) {
            // IPv4
            const parts = ip.split('.').map(Number);
            if (parts.length !== 4 || parts.some(p => p < 0 || p > 255)) return null;
            return BigInt(parts[0]) * 256n ** 3n + BigInt(parts[1]) * 256n ** 2n + BigInt(parts[2]) * 256n + BigInt(parts[3]);
        } else if (ip.includes(':')) {
            // IPv6
            try {
                // Expand :: and normalize
                const sections = ip.split('::');
                let left = sections[0] ? sections[0].split(':') : [];
                let right = sections[1] ? sections[1].split(':') : [];
                const missing = 8 - (left.length + right.length);
                const zeros = Array(missing).fill('0');
                const full = [...left, ...zeros, ...right];

                if (full.length !== 8) return null;

                let result = 0n;
                for (let block of full) {
                    const value = BigInt('0x' + block.padStart(4, '0'));
                    result = (result << 16n) + value;
                }
                return result;
            } catch (e) {
                return null;
            }
        }

        return null;
    }

    function valid_IP(ip) {
        const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/;
        const ipv6Regex = /^((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6}))$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    function addToPendingList() {
        const type = document.getElementById('singleIpOption').checked ? 'single' : 'range';


        clearValidation();
        let entry = {};

        if (type === 'single') {
            const ip = document.getElementById('ip').value.trim();
            if (!valid_IP(ip)) {
                markInvalid('ip');
                console.log(ip)
                showAlert("Invalid IPv4/IPv6 address.");
                return;
            }

            if (isDuplicateSingle(ip)) {
                markInvalid('ip');
                showAlert("This IP already exists or overlaps with a range.");
                return;
            }

            entry = { type: 'single', ip };
        } else {
            const start = document.getElementById('start_ip').value.trim();
            const end = document.getElementById('end_ip').value.trim();

            if (!valid_IP(start)) {
                markInvalid('start_ip');
                showAlert("Invalid Start IP.");
                return;
            }
            if (!valid_IP(end)) {
                markInvalid('end_ip');
                showAlert("Invalid End IP.");
                return;
            }

            if (ipToNumber(start) > ipToNumber(end)) {
                markInvalid('start_ip');
                markInvalid('end_ip');
                showAlert("Start IP must be less than or equal to End IP.");
                return;
            }

            if (isDuplicateRange(start, end)) {
                showAlert("This IP range overlaps with an existing IP or range.");
                return;
            }

            entry = { type: 'range', start_ip: start, end_ip: end };
        }

        // Lý do
        const reason = document.getElementById('reasonSelect').value;
        entry.reason = (reason === 'custom')
            ? document.getElementById('customReason').value.trim()
            : reason;

        pendingEntries.push(entry);
        updatePendingList();
        hideAlert();
        document.getElementById('blacklistForm').reset();
        toggleInputType('single');
        clearValidation();
    }

    function isDuplicateSingle(newIp) {
        const newNum = ipToNumber(newIp);

        return pendingEntries.some(entry => {
            if (entry.type === 'single') {
                return entry.ip === newIp;
            } else {
                const start = ipToNumber(entry.start_ip);
                const end = ipToNumber(entry.end_ip);
                return newNum >= start && newNum <= end;
            }
        });
    }

    function isDuplicateRange(newStart, newEnd) {
        const newStartNum = ipToNumber(newStart);
        const newEndNum = ipToNumber(newEnd);

        return pendingEntries.some(entry => {
            if (entry.type === 'single') {
                const ipNum = ipToNumber(entry.ip);
                return ipNum >= newStartNum && ipNum <= newEndNum;
            } else {
                const start = ipToNumber(entry.start_ip);
                const end = ipToNumber(entry.end_ip);
                // Kiểm tra xem hai đoạn có giao nhau không
                return !(newEndNum < start || newStartNum > end);
            }
        });
    }

    function updatePendingList() {
        const list = document.getElementById('pendingList');
        list.innerHTML = "";
        pendingEntries.forEach((entry, i) => {
            const li = document.createElement("li");
            li.className = "list-group-item d-flex justify-content-between align-items-center";
            li.innerHTML = `
        ${entry.type === 'single' ? entry.ip : entry.start_ip + ' - ' + entry.end_ip} (${entry.reason})
        <button class="btn btn-sm btn-outline-danger" onclick="removeEntry(${i})">&times;</button>
      `;
            list.appendChild(li);
        });
    }

    function removeEntry(index) {
        pendingEntries.splice(index, 1);
        updatePendingList();
    }

    function submitPendingList() {
        if (pendingEntries.length === 0) {
            showAlert("No IPs in the pending list.");
            return;
        }
        document.getElementById('entriesData').value = JSON.stringify(pendingEntries);
        document.getElementById('submitForm').submit();
    }

    let domainEntries = [];

    function toggleCustomReason(selectId, inputId) {
        const select = document.getElementById(selectId);
        const input = document.getElementById(inputId);
        input.style.display = (select.value === 'custom') ? 'block' : 'none';
    }

    function showDomainAlert(msg) {
        const box = document.getElementById('domainAlertBox');
        const text = document.getElementById('domainAlertMessage');
        text.textContent = msg;
        box.classList.remove('d-none');
        box.classList.add('show');
        setTimeout(hideDomainAlert, 4000);
    }

    function hideDomainAlert() {
        const box = document.getElementById('domainAlertBox');
        box.classList.add('d-none');
        box.classList.remove('show');
    }

    function isValidDomain(domain) {
        const pattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
        return pattern.test(domain);
    }

    function domainMatches(d1, d2) {
        return d1 === d2 || d1.endsWith("." + d2) || d2.endsWith("." + d1);
    }

    function isDuplicateDomain(newDomain) {
        newDomain = newDomain.toLowerCase();
        return domainEntries.some(entry => domainMatches(entry.domain, newDomain));
    }

    function addDomainToList() {
        const input = document.getElementById('domain');
        const rawDomain = input.value.trim().toLowerCase();
        input.classList.remove('is-invalid');

        if (!isValidDomain(rawDomain)) {
            input.classList.add('is-invalid');
            showDomainAlert("Invalid domain name.");
            return;
        }

        if (isDuplicateDomain(rawDomain)) {
            input.classList.add('is-invalid');
            showDomainAlert("This domain or related subdomain is already in the list.");
            return;
        }

        const reasonSelect = document.getElementById('domainReasonSelect');
        const reason = (reasonSelect.value === 'custom')
            ? document.getElementById('domainCustomReason').value.trim()
            : reasonSelect.value;

        domainEntries.push({ domain: rawDomain, reason });
        updatePendingDomainList();
        document.getElementById('domainBlacklistForm').reset();
        hideDomainAlert();
    }

    function updatePendingDomainList() {
        const list = document.getElementById('pendingDomainList');
        list.innerHTML = "";
        domainEntries.forEach((entry, index) => {
            const li = document.createElement("li");
            li.className = "list-group-item d-flex justify-content-between align-items-center";
            li.innerHTML = `
      ${entry.domain} (${entry.reason})
      <button class="btn btn-sm btn-outline-danger" onclick="removeDomain(${index})">&times;</button>
    `;
            list.appendChild(li);
        });
    }

    function removeDomain(index) {
        domainEntries.splice(index, 1);
        updatePendingDomainList();
    }

    function submitDomainList() {
        if (domainEntries.length === 0) {
            showDomainAlert("No domains in the list.");
            return;
        }
        document.getElementById('domainEntriesData').value = JSON.stringify(domainEntries);
        document.getElementById('submitDomainForm').submit();
    }





});

class BlacklistTable {
    constructor() {
        this.originalData = [];
        this.filteredData = [];
        this.currentPage = 1;
        this.entriesPerPage = 10;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.searchQuery = '';
        this.statusFilter = 'all';
        
        this.init();
    }
    
    init() {
        this.loadOriginalData();
        this.restoreState();
        this.bindEvents();
        this.updateTable();
    }
    
    loadOriginalData() {
        const rows = document.querySelectorAll('#tableBody tr');
        this.originalData = Array.from(rows).map(row => ({
            ip: row.dataset.ip,
            reason: row.dataset.reason,
            date: row.dataset.date,
            status: row.dataset.status,
            element: row.cloneNode(true)
        }));
        this.filteredData = [...this.originalData];
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
        
        // Restore status filter
        this.statusFilter = urlParams.get('status') || 'all';
        document.getElementById('statusFilter').value = this.statusFilter;
        
        // Restore sort
        this.sortColumn = urlParams.get('sort') || null;
        this.sortDirection = urlParams.get('dir') || 'asc';
        
        // Restore current page
        this.currentPage = parseInt(urlParams.get('page')) || 1;
        
        // Apply filters
        if (this.searchQuery) {
            this.applySearch();
        }
        if (this.statusFilter !== 'all') {
            this.applyStatusFilter();
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
        if (this.statusFilter !== 'all') urlParams.set('status', this.statusFilter);
        if (this.sortColumn) {
            urlParams.set('sort', this.sortColumn);
            urlParams.set('dir', this.sortDirection);
        }
        if (this.currentPage !== 1) urlParams.set('page', this.currentPage);
        
        const newUrl = window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
        window.history.replaceState({}, '', newUrl);
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
        
        // Status filter event
        document.getElementById('statusFilter').addEventListener('change', (e) => {
            this.filterByStatus(e.target.value);
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
            
            if (this.sortColumn === 'date') {
                // Date sorting
                const aDate = new Date(aVal);
                const bDate = new Date(bVal);
                const comparison = aDate - bDate;
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
                item.ip.toLowerCase().includes(searchTerm) ||
                item.reason.toLowerCase().includes(searchTerm)
            );
        }
        
        // Re-apply status filter if active
        if (this.statusFilter !== 'all') {
            this.applyStatusFilter();
        }
    }
    
    filterByStatus(status) {
        this.statusFilter = status;
        this.applyStatusFilter();
        this.currentPage = 1;
        this.updateTable();
        this.saveState();
    }
    
    applyStatusFilter() {
        let baseData = this.originalData;
        
        // Apply search filter first if active
        if (this.searchQuery.trim()) {
            const searchTerm = this.searchQuery.toLowerCase();
            baseData = baseData.filter(item => 
                item.ip.toLowerCase().includes(searchTerm) ||
                item.reason.toLowerCase().includes(searchTerm)
            );
        }
        
        // Then apply status filter
        if (this.statusFilter === 'all') {
            this.filteredData = [...baseData];
        } else {
            this.filteredData = baseData.filter(item => 
                item.status === this.statusFilter
            );
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
let blacklistTable;
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('tableBody')) {
        blacklistTable = new BlacklistTable();
    }
});

// Modal functionality
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
document.addEventListener('DOMContentLoaded', function() {
    const reasonSelect = document.getElementById('reasonSelect');
    const customReason = document.getElementById('customReason');
    
    if (reasonSelect && customReason) {
        reasonSelect.addEventListener('change', function() {
            if (this.value !== 'custom') {
                customReason.value = this.value;
            }
        });
        
        // Set initial value
        customReason.value = reasonSelect.value;
    }
});