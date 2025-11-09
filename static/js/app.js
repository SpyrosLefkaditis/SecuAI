/**
 * SecuAI Frontend JavaScript
 * Handles AJAX calls, UI interactions, and real-time updates
 */

// Global configuration
const SECUAI_CONFIG = {
    refreshInterval: 30000, // 30 seconds
    apiTimeout: 10000, // 10 seconds
    maxRetries: 3
};

/**
 * Theme management functions
 */
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    // Update theme icon
    const themeIcon = document.getElementById('theme-icon');
    if (newTheme === 'dark') {
        themeIcon.className = 'bi bi-sun-fill';
    } else {
        themeIcon.className = 'bi bi-moon-fill';
    }
    
    console.log(`🎨 Theme switched to: ${newTheme}`);
}

function initializeTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    const themeIcon = document.getElementById('theme-icon');
    if (themeIcon) {
        if (savedTheme === 'dark') {
            themeIcon.className = 'bi bi-sun-fill';
        } else {
            themeIcon.className = 'bi bi-moon-fill';
        }
    }
    
    console.log(`🎨 Theme initialized: ${savedTheme}`);
}

// Initialize on document ready
$(document).ready(function() {
    console.log('🚀 SecuAI Dashboard initialized');
    
    // Initialize theme
    initializeTheme();
    
    // Start periodic updates
    startPeriodicUpdates();
    
    // Initialize tooltips
    $('[data-bs-toggle="tooltip"]').tooltip();
    
    // Setup form handlers
    setupEventHandlers();
});

/**
 * Start periodic updates for dashboard data
 */
function startPeriodicUpdates() {
    // Update alerts every 30 seconds
    setInterval(refreshAlerts, SECUAI_CONFIG.refreshInterval);
    
    // Update system status
    setInterval(updateSystemStatus, SECUAI_CONFIG.refreshInterval);
}

/**
 * Setup event handlers for forms and buttons
 */
function setupEventHandlers() {
    // Upload form handler
    $('#upload-form').on('submit', function(e) {
        const fileInput = $('#logfile')[0];
        if (!fileInput.files.length) {
            e.preventDefault();
            showAlert('Please select a log file to upload', 'warning');
            return false;
        }
        
        // Show loading state
        const submitBtn = $(this).find('button[type="submit"]');
        submitBtn.prop('disabled', true).html('<i class="bi bi-hourglass-split"></i> Analyzing...');
    });
    
    // Real-time log analysis
    $('#log-text').on('input', debounce(function() {
        const text = $(this).val().trim();
        if (text.length > 100) { // Minimum text for analysis
            $('#analysis-preview').show();
        }
    }, 1000));
}

/**
 * Analyze log text via API
 */
function analyzeLogText() {
    const logText = $('#log-text').val().trim();
    
    if (!logText) {
        showAlert('Please enter some log text to analyze', 'warning');
        return;
    }
    
    // Show loading state
    const btn = event.target;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analyzing...';
    
    $.ajax({
        url: '/api/analyze',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ log_text: logText }),
        timeout: SECUAI_CONFIG.apiTimeout,
        success: function(response) {
            displayAnalysisResults(response);
            if (response.count > 0) {
                showAlert(`Analysis complete: ${response.count} findings detected`, 'success');
                refreshAlerts(); // Refresh alerts table
            } else {
                showAlert('Analysis complete: No security threats detected', 'info');
            }
        },
        error: function(xhr, status, error) {
            console.error('Analysis error:', error);
            showAlert('Analysis failed: ' + getErrorMessage(xhr), 'danger');
        },
        complete: function() {
            // Restore button state
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    });
}

/**
 * Display analysis results in the UI
 */
function displayAnalysisResults(response) {
    const resultsDiv = $('#analysis-results');
    const summaryDiv = $('#analysis-summary');
    
    if (response.findings && response.findings.length > 0) {
        let html = `<strong>Found ${response.findings.length} security findings:</strong><ul class="mt-2">`;
        
        response.findings.forEach(finding => {
            const confidenceClass = finding.confidence >= 0.8 ? 'danger' : 
                                   finding.confidence >= 0.6 ? 'warning' : 'info';
            const confidencePercent = Math.round(finding.confidence * 100);
            
            html += `
                <li class="mb-1">
                    <span class="badge bg-secondary">${finding.ip}</span>
                    ${finding.reason}
                    <span class="badge bg-${confidenceClass}">${confidencePercent}% confidence</span>
                </li>`;
        });
        
        html += '</ul>';
        summaryDiv.html(html);
    } else {
        summaryDiv.html('<i class="bi bi-check-circle text-success"></i> No security threats detected in the log data.');
    }
    
    resultsDiv.show();
}

/**
 * Recommend blocking an IP
 */
function recommendBlock(ip) {
    if (!confirm(`Recommend blocking IP ${ip}?`)) {
        return;
    }
    
    performBlockAction(ip, 'recommend', 'Recommendation sent');
}

/**
 * Approve and block an IP
 */
function approveBlock(ip) {
    if (!confirm(`Approve blocking of IP ${ip}? This will simulate the block.`)) {
        return;
    }
    
    performBlockAction(ip, 'approve', 'Block approved and simulated');
}

/**
 * Perform block action via API
 */
function performBlockAction(ip, action, successMessage) {
    const btn = event.target.closest('button');
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i>';
    
    $.ajax({
        url: '/api/firewall/blacklist',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: ip, reason: `Block action: ${action}` }),
        timeout: SECUAI_CONFIG.apiTimeout,
        success: function(response) {
            showAlert(`${successMessage}: ${ip}`, 'success');
            refreshBlocks(); // Refresh blocks list
            refreshAlerts(); // Refresh alerts
        },
        error: function(xhr, status, error) {
            console.error('Block error:', error);
            showAlert('Block operation failed: ' + getErrorMessage(xhr), 'danger');
        },
        complete: function() {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    });
}

/**
 * Ignore an alert
 */
function ignoreAlert(alertId) {
    if (!confirm('Mark this alert as ignored?')) {
        return;
    }
    
    // Note: This would need a backend endpoint to update alert status
    showAlert('Alert ignored (demo - backend endpoint needed)', 'info');
}

/**
 * Refresh alerts table
 */
function refreshAlerts() {
    // In a real implementation, this would fetch fresh data
    // For now, we'll just show a refresh indicator
    const refreshBtn = $('.btn:contains("Refresh")');
    if (refreshBtn.length) {
        refreshBtn.html('<i class="bi bi-hourglass-split"></i> Refreshing...');
        
        setTimeout(() => {
            refreshBtn.html('<i class="bi bi-arrow-clockwise"></i> Refresh');
        }, 1000);
    }
}

/**
 * Refresh blocks list (no-op since blocks section removed)
 */
function refreshBlocks() {
    // Blocks section has been removed - functionality moved to firewall page
    console.log('Blocks section removed - use firewall page for IP management');
}

/**
 * Update blocks list in UI
 */
function updateBlocksList(blocks) {
    const blocksList = $('#blocks-list');
    
    if (!blocks || blocks.length === 0) {
        blocksList.html(`
            <div class="text-center text-muted">
                <i class="bi bi-info-circle"></i> No active blocks
            </div>
        `);
        return;
    }
    
    let html = '';
    blocks.forEach(block => {
        const createdAt = new Date(block.created_at);
        const timeStr = createdAt.toLocaleDateString() + ' ' + createdAt.toLocaleTimeString();
        
        html += `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                <div>
                    <strong>${block.ip}</strong><br>
                    <small class="text-muted">
                        ${timeStr}
                        ${!block.applied ? '<span class="badge bg-warning">Simulated</span>' : ''}
                    </small>
                </div>
                <button class="btn btn-sm btn-outline-danger" onclick="unblockIP('${block.ip}')">
                    <i class="bi bi-unlock"></i>
                </button>
            </div>
        `;
    });
    
    blocksList.html(html);
}

/**
 * Unblock an IP
 */
function unblockIP(ip) {
    if (!confirm(`Remove block for IP ${ip}?`)) {
        return;
    }
    
    $.ajax({
        url: '/api/firewall/unblock',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: ip }),
        timeout: SECUAI_CONFIG.apiTimeout,
        success: function(response) {
            showAlert(`Successfully unblocked IP ${ip}`, 'success');
            // Refresh the current page to update the UI
            setTimeout(() => location.reload(), 1000);
        },
        error: function(xhr, status, error) {
            console.error('Unblock error:', error);
            showAlert(`Failed to unblock IP ${ip}: ${getErrorMessage(xhr)}`, 'danger');
        }
    });
}

/**
 * Load honeypot feed data
 */
function loadHoneypotFeed() {
    const btn = event.target;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Loading...';
    
    // Simulate loading honeypot feed
    setTimeout(() => {
        const honeypotData = $('#honeypot-data');
        honeypotData.html(`
            <div class="mb-2">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge bg-danger">203.0.113.200</span>
                    <small class="text-muted">High Risk</small>
                </div>
                <small class="text-muted">Web scanning, SQL injection attempts</small>
            </div>
            <div class="mb-2">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge bg-warning">198.51.100.150</span>
                    <small class="text-muted">Medium Risk</small>
                </div>
                <small class="text-muted">Port scanning activity</small>
            </div>
            <div class="text-center mt-3">
                <small class="text-success">
                    <i class="bi bi-check-circle"></i> Feed loaded successfully
                </small>
            </div>
        `);
        
        // Restore button
        btn.disabled = false;
        btn.innerHTML = originalHtml;
        
        showAlert('Honeypot feed loaded successfully', 'success');
    }, 2000);
}

/**
 * Test Analysis API
 */
function testAnalysisAPI() {
    const testLogs = $('#api-test-logs').val().trim();
    
    if (!testLogs) {
        showAlert('Please enter test logs', 'warning');
        return;
    }
    
    const btn = event.target;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Testing...';
    
    $.ajax({
        url: '/api/analyze',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ log_text: testLogs }),
        timeout: SECUAI_CONFIG.apiTimeout,
        success: function(response) {
            displayAPIResponse('Analysis API Test', response);
            showAlert('API test completed successfully', 'success');
        },
        error: function(xhr, status, error) {
            displayAPIResponse('Analysis API Error', { 
                error: getErrorMessage(xhr),
                status: xhr.status 
            });
            showAlert('API test failed', 'danger');
        },
        complete: function() {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    });
}

/**
 * Test Block API
 */
function testBlockAPI(action) {
    const testIP = $('#test-ip').val().trim();
    
    if (!testIP) {
        showAlert('Please enter a test IP address', 'warning');
        return;
    }
    
    const btn = event.target;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Testing...';
    
    $.ajax({
        url: '/api/firewall/blacklist',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: testIP, reason: `API test - ${action} action` }),
        timeout: SECUAI_CONFIG.apiTimeout,
        success: function(response) {
            displayAPIResponse(`Block API Test (${action})`, response);
            showAlert(`Block API test (${action}) completed`, 'success');
        },
        error: function(xhr, status, error) {
            displayAPIResponse(`Block API Error (${action})`, { 
                error: getErrorMessage(xhr),
                status: xhr.status 
            });
            showAlert(`Block API test (${action}) failed`, 'danger');
        },
        complete: function() {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    });
}

/**
 * Display API response in the demo section
 */
function displayAPIResponse(title, response) {
    const responseDiv = $('#api-response');
    const formattedResponse = JSON.stringify(response, null, 2);
    
    responseDiv.html(`<strong>${title}:</strong>\n${formattedResponse}`);
    responseDiv.show();
}

/**
 * Update system status indicator
 */
function updateSystemStatus() {
    // Simple status check - in real implementation would ping health endpoint
    $('#system-status').text('Online').removeClass('text-danger').addClass('text-success');
}

/**
 * Scroll to a specific section
 */
function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
    }
}

/**
 * Show alert message
 */
function showAlert(message, type = 'info') {
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
 * Debounce function to limit API calls
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

/**
 * Get confidence level class for styling
 */
function getConfidenceClass(confidence) {
    if (confidence >= 0.8) return 'danger';
    if (confidence >= 0.6) return 'warning';
    return 'info';
}

// Export functions for global access
window.SecuAI = {
    analyzeLogText,
    recommendBlock,
    approveBlock,
    ignoreAlert,
    refreshAlerts,
    refreshBlocks,
    unblockIP,
    loadHoneypotFeed,
    testAnalysisAPI,
    testBlockAPI,
    scrollToSection,
    showAlert
};