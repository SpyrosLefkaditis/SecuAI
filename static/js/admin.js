/**
 * SecuAI Admin Panel JavaScript
 * Handles admin-specific functionality and API calls
 */

// Initialize admin panel
$(document).ready(function() {
    console.log('🔧 SecuAI Admin Panel initialized');
    
    // Initialize tooltips and popovers
    $('[data-bs-toggle="tooltip"]').tooltip();
    $('[data-bs-toggle="popover"]').popover();
    
    // Setup confidence threshold slider
    setupConfidenceSlider();
    
    // Load initial data
    loadAdminData();
});

/**
 * Setup confidence threshold slider
 */
function setupConfidenceSlider() {
    const slider = $('#confidence-threshold');
    const valueDisplay = $('#threshold-value');
    
    slider.on('input', function() {
        valueDisplay.text(this.value);
    });
}

/**
 * Load admin panel data
 */
function loadAdminData() {
    // This would typically load fresh admin data
    console.log('📊 Loading admin data...');
}

/**
 * Review an alert (mark as reviewed)
 */
function reviewAlert(alertId) {
    if (!confirm('Mark this alert as reviewed?')) {
        return;
    }
    
    const btn = event.target;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i>';
    
    // Note: In real implementation, this would call a backend API
    setTimeout(() => {
        const row = btn.closest('tr');
        const statusCell = row.querySelector('td:nth-child(7)'); // Status column
        statusCell.innerHTML = '<span class="badge bg-success">Reviewed</span>';
        
        // Remove action buttons
        const actionsCell = row.querySelector('td:nth-child(8)');
        actionsCell.innerHTML = `
            <button class="btn btn-sm btn-info" onclick="viewAlertDetails(${alertId})">
                <i class="bi bi-eye"></i> Details
            </button>
        `;
        
        showAdminAlert(`Alert ${alertId} marked as reviewed`, 'success');
    }, 1000);
}

/**
 * Block IP from alert
 */
function blockFromAlert(ip, alertId) {
    if (!confirm(`Block IP ${ip} and mark alert as resolved?`)) {
        return;
    }
    
    const btn = event.target;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i>';
    
    $.ajax({
        url: '/api/block',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: ip, action: 'approve' }),
        success: function(response) {
            // Update alert status
            const row = btn.closest('tr');
            const statusCell = row.querySelector('td:nth-child(7)');
            statusCell.innerHTML = '<span class="badge bg-danger">Blocked</span>';
            
            // Remove action buttons
            const actionsCell = row.querySelector('td:nth-child(8)');
            actionsCell.innerHTML = `
                <button class="btn btn-sm btn-info" onclick="viewAlertDetails(${alertId})">
                    <i class="bi bi-eye"></i> Details
                </button>
            `;
            
            showAdminAlert(`IP ${ip} blocked successfully`, 'success');
        },
        error: function(xhr, status, error) {
            showAdminAlert('Block operation failed: ' + getErrorMessage(xhr), 'danger');
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    });
}

/**
 * View alert details in modal
 */
function viewAlertDetails(alertId) {
    const modal = new bootstrap.Modal(document.getElementById('alertDetailsModal'));
    const content = $('#alert-details-content');
    
    // Show loading state
    content.html(`
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading alert details...</p>
        </div>
    `);
    
    modal.show();
    
    // Simulate loading alert details (in real app, would fetch from API)
    setTimeout(() => {
        content.html(`
            <div class="row">
                <div class="col-md-6">
                    <h6>Alert Information</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Alert ID:</strong></td><td>${alertId}</td></tr>
                        <tr><td><strong>IP Address:</strong></td><td>192.168.1.100</td></tr>
                        <tr><td><strong>Threat Type:</strong></td><td>Brute Force Login</td></tr>
                        <tr><td><strong>Confidence:</strong></td><td>85%</td></tr>
                        <tr><td><strong>Source:</strong></td><td>auth.log</td></tr>
                        <tr><td><strong>Status:</strong></td><td>New</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>Technical Details</h6>
                    <pre class="bg-light p-2 rounded"><code>{
  "attack_type": "brute_force_login",
  "attempt_count": 5,
  "detection_rule": "failed_login_detection",
  "ml_insights": {
    "confidence_adjustment": 0.1,
    "threat_level": "high",
    "geolocation": {
      "country": "Unknown",
      "is_tor": false
    }
  }
}</code></pre>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-12">
                    <h6>Raw Log Entries</h6>
                    <div class="bg-dark text-light p-3 rounded" style="font-family: monospace; font-size: 0.85em;">
                        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2<br>
                        Oct 15 10:30:20 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2<br>
                        Oct 15 10:30:25 server sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2<br>
                        Oct 15 10:30:30 server sshd[12348]: Failed password for test from 192.168.1.100 port 22 ssh2<br>
                        Oct 15 10:30:35 server sshd[12349]: Failed password for guest from 192.168.1.100 port 22 ssh2
                    </div>
                </div>
            </div>
        `);
    }, 1000);
}

/**
 * Show add whitelist modal
 */
function showAddWhitelistModal() {
    const modal = new bootstrap.Modal(document.getElementById('addWhitelistModal'));
    
    // Clear form
    $('#whitelist-ip').val('');
    $('#whitelist-description').val('');
    
    modal.show();
}

/**
 * Add IP to whitelist
 */
function addToWhitelist() {
    const ip = $('#whitelist-ip').val().trim();
    const description = $('#whitelist-description').val().trim();
    
    if (!ip) {
        showAdminAlert('Please enter an IP address', 'warning');
        return;
    }
    
    // Basic IP validation
    if (!isValidIP(ip)) {
        showAdminAlert('Please enter a valid IP address or CIDR range', 'warning');
        return;
    }
    
    // Note: In real implementation, this would call a backend API
    const modal = bootstrap.Modal.getInstance(document.getElementById('addWhitelistModal'));
    modal.hide();
    
    // Simulate adding to whitelist
    setTimeout(() => {
        // Add row to whitelist table
        const table = document.querySelector('#whitelist-panel tbody');
        const newRow = table.insertRow(0);
        
        newRow.innerHTML = `
            <td><span class="badge bg-success">${ip}</span></td>
            <td>${description || 'No description'}</td>
            <td><small class="text-muted">${new Date().toLocaleDateString()}</small></td>
            <td><span class="badge bg-success">Active</span></td>
            <td>
                <div class="btn-group" role="group">
                    <button class="btn btn-sm btn-warning" onclick="toggleWhitelist(999, false)">
                        <i class="bi bi-pause"></i> Disable
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteWhitelist(999)">
                        <i class="bi bi-trash"></i> Delete
                    </button>
                </div>
            </td>
        `;
        
        showAdminAlert(`IP ${ip} added to whitelist`, 'success');
    }, 500);
}

/**
 * Toggle whitelist entry status
 */
function toggleWhitelist(entryId, enable) {
    const action = enable ? 'enable' : 'disable';
    
    if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} this whitelist entry?`)) {
        return;
    }
    
    const btn = event.target;
    const row = btn.closest('tr');
    const statusCell = row.querySelector('td:nth-child(4)');
    const actionsCell = row.querySelector('td:nth-child(5)');
    
    // Update UI
    if (enable) {
        statusCell.innerHTML = '<span class="badge bg-success">Active</span>';
        actionsCell.innerHTML = `
            <div class="btn-group" role="group">
                <button class="btn btn-sm btn-warning" onclick="toggleWhitelist(${entryId}, false)">
                    <i class="bi bi-pause"></i> Disable
                </button>
                <button class="btn btn-sm btn-danger" onclick="deleteWhitelist(${entryId})">
                    <i class="bi bi-trash"></i> Delete
                </button>
            </div>
        `;
    } else {
        statusCell.innerHTML = '<span class="badge bg-secondary">Inactive</span>';
        actionsCell.innerHTML = `
            <div class="btn-group" role="group">
                <button class="btn btn-sm btn-success" onclick="toggleWhitelist(${entryId}, true)">
                    <i class="bi bi-play"></i> Enable
                </button>
                <button class="btn btn-sm btn-danger" onclick="deleteWhitelist(${entryId})">
                    <i class="bi bi-trash"></i> Delete
                </button>
            </div>
        `;
    }
    
    showAdminAlert(`Whitelist entry ${action}d`, 'success');
}

/**
 * Delete whitelist entry
 */
function deleteWhitelist(entryId) {
    if (!confirm('Permanently delete this whitelist entry?')) {
        return;
    }
    
    const btn = event.target;
    const row = btn.closest('tr');
    
    // Remove row with animation
    $(row).fadeOut(500, function() {
        $(this).remove();
    });
    
    showAdminAlert('Whitelist entry deleted', 'success');
}

/**
 * Show change password modal
 */
function showChangePasswordModal() {
    // In a real implementation, this would show a password change modal
    showAdminAlert('Password change feature would be implemented here', 'info');
}

/**
 * Validate IP address or CIDR range
 */
function isValidIP(ip) {
    // Basic validation for IPv4 addresses and CIDR notation
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Show admin alert message
 */
function showAdminAlert(message, type = 'info') {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="bi bi-${getAlertIcon(type)}"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // Insert at top of container
    $('.container-fluid').prepend(alertHtml);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        $('.alert').first().alert('close');
    }, 5000);
}

/**
 * Get appropriate icon for alert type
 */
function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * Extract error message from XHR response
 */
function getErrorMessage(xhr) {
    try {
        const response = JSON.parse(xhr.responseText);
        return response.error || response.message || 'Unknown error';
    } catch (e) {
        return xhr.statusText || 'Network error';
    }
}

/**
 * Export admin functions
 */
window.SecuAIAdmin = {
    reviewAlert,
    blockFromAlert,
    viewAlertDetails,
    showAddWhitelistModal,
    addToWhitelist,
    toggleWhitelist,
    deleteWhitelist,
    showChangePasswordModal,
    showAdminAlert
};