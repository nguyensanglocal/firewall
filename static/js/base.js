
// function blockIP(ip, alert_type) {
//     if (confirm(`Are you sure you want to block IP ${ip}?`)) {
//         fetch('/add_blacklist', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/x-www-form-urlencoded',
//                 'X-Requested-With': 'XMLHttpRequest'
//             },
//             body: `ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent('Blocked from alert: ' + alert_type)}`
//         }).then(response => {
//             if (response.ok) {
//                 saveToastMessage(`✅ IP <strong>${ip}</strong> has been blocked.`, 'success');
//             } else {
//                 showToast(`❌ Failed to block IP: ${ip || 'Unknown error'}`, 'danger');
//             }
//         }).catch((error) => {
//             showToast(`❌ Error: ${error.message}`, 'danger');

//         });
//     }
// }

function createModal(modalId, title, bodyContent, confirmCallback) {
    // Tạo HTML cho modal
    const modalHTML = `
    <div class="modal fade" id="${modalId}" tabindex="-1" aria-labelledby="${modalId}-label" aria-hidden="true">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="${modalId}-label">${title}</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <p>${bodyContent}</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-danger" id="${modalId}-confirm">Confirm</button>
          </div>
        </div>
      </div>
    </div>`;
    
    // Gắn vào body
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Hiển thị modal
    const modalEl = document.getElementById(modalId);
    const modal = new bootstrap.Modal(modalEl);
    return modal;
}

function blockIP(ip, alert_type) {
    const modalId = `blockModal-${Date.now()}`; // Unique ID
    const title = 'Confirm Block IP';
    // Nội dung body với thông tin IP
    const bodyContent = `Are you sure you want to block the IP <strong>${ip}</strong>?`;
    const modal = createModal(modalId, title, bodyContent);
    modal.show();

    // Xử lý khi bấm Confirm
    document.getElementById(`${modalId}-confirm`).addEventListener('click', () => {
        fetch('/add_blacklist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: `ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent('Blocked from alert: ' + alert_type)}`
        }).then(response => {
            if (response.ok) {
                saveToastMessage(`✅ IP <strong>${ip}</strong> has been blocked.`, 'success');
            } else {
                showToast(`❌ Failed to block IP: ${ip}`, 'danger');
            }
        }).catch(error => {
            showToast(`❌ Error: ${error.message}`, 'danger');
        });

        // Đóng modal và xóa khỏi DOM sau khi dùng
        modal.hide();
        modalEl.addEventListener('hidden.bs.modal', () => {
            modalEl.remove();
        });
    });
}


function showToast(message, type = 'success') {
    const toastContainer = document.getElementById('toastContainer');
    const toastId = `toast-${Date.now()}`;

    // Đặt màu nền nhẹ tùy theo loại
    const bgMap = {
        success: 'bg-success-subtle text-success',
        danger: 'bg-danger-subtle text-danger',
        warning: 'bg-warning-subtle text-warning',
        info: 'bg-info-subtle text-info'
    };
    const bgClass = bgMap[type] || 'bg-secondary-subtle text-body';

    const toastHTML = `
    <div id="${toastId}" class="toast border rounded-3 shadow-sm ${bgClass} mb-2" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex align-items-center">
        <div class="toast-body fw-semibold">
          ${message}
        </div>
        <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>`;

    toastContainer.insertAdjacentHTML('beforeend', toastHTML);

    const toastEl = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastEl, { delay: 3000 });
    toast.show();

    toastEl.addEventListener('hidden.bs.toast', () => {
        toastEl.remove();
    });
}

window.addEventListener('DOMContentLoaded', () => {
    const toastData = localStorage.getItem('toastMessage');
    if (toastData) {
        const { message, type } = JSON.parse(toastData);
        showToast(message, type);
        localStorage.removeItem('toastMessage');
    }
});

function saveToastMessage(message, type = 'success') {
    localStorage.setItem('toastMessage', JSON.stringify({ message:message, type:type }));
    location.reload();
}


function unBlockIP(ip) {
    const modalId = `unblockModal-${Date.now()}`;
    const title = 'Confirm Unblock IP';
    // Nội dung body với thông tin IP
    const bodyContent = `Are you sure you want to remove the IP <strong>${ip}</strong> from the blacklist? This action cannot be undone.`;

    // Tạo modal
    const modal = createModal(modalId, title, bodyContent);
    modal.show();
    
    const url = `/remove_blacklist/${ip}`; // Sử dụng URL mặc định nếu không có

    // Sự kiện click Confirm
    document.getElementById(`${modalId}-confirm`).addEventListener('click', async () => {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();

            if (response.ok && result.success) {
                saveToastMessage(`✅ Successfully removed <strong>${result.ip}</strong> from blacklist`, 'success');
            } else {
                showToast(`❌ Failed to remove IP: ${result.error || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            showToast(`❌ Error: ${error.message}`, 'danger');
        }

        // Đóng và xóa modal khỏi DOM
        modal.hide();
        modalEl.addEventListener('hidden.bs.modal', () => {
            modalEl.remove();
        });
    });
}
