// Khởi tạo Chart.js khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', () => {
    const contentArea = document.getElementById('main-content');
    const navLinks = {
        dashboard: document.getElementById('nav-dashboard'),
        alert: document.getElementById('nav-alert'),
        network: document.getElementById('nav-network'),
        log: document.getElementById('nav-log'),
        setting: document.getElementById('nav-setting')
    };

    async function loadPage(pageName) {
        try {
            let filePath = `${pageName}.html`;
            const response = await fetch(filePath);
            if (!response.ok) {
                // Handle error, e.g., show a 404 message in contentArea
                contentArea.innerHTML = `<p>Error: Could not load ${pageName}.html. Status: ${response.status}</p>`;
                console.error(`Failed to load ${filePath}: ${response.status}`);
                return;
            }
            const htmlContent = await response.text();
            contentArea.innerHTML = htmlContent;
            updateActiveLink(pageName);

            if (pageName === 'dashboard') {
                initializeDashboardElements();
                initializeOrReinitializeCharts(); // Initialize/Reinitialize charts AFTER new HTML is loaded
                addDashboardEventListeners();
            }
        } catch (error) {
            console.error('Lỗi khi tải trang:', error);
            contentArea.innerHTML = `<p>Error loading page: ${error.message}</p>`;
        }
    }

    function updateActiveLink(activePage) {
        for (const id in navLinks) {
            if (navLinks[id]) {
                navLinks[id].classList.remove('active');
            }
        }
        if (navLinks[activePage]) {
            navLinks[activePage].classList.add('active');
        }
    }

    // Gán sự kiện click
    if (navLinks.dashboard) navLinks.dashboard.addEventListener('click', (e) => { e.preventDefault(); loadPage('dashboard'); });
    if (navLinks.alert) navLinks.alert.addEventListener('click', (e) => { e.preventDefault(); loadPage('alert'); });
    if (navLinks.network) navLinks.network.addEventListener('click', (e) => { e.preventDefault(); loadPage('network'); });
    if (navLinks.log) navLinks.log.addEventListener('click', (e) => { e.preventDefault(); loadPage('log'); });
    if (navLinks.setting) navLinks.setting.addEventListener('click', (e) => { e.preventDefault(); loadPage('setting'); });

    // Tải trang mặc định
    loadPage('dashboard');
});

// --- DOM Element References (dynamically set in initializeDashboardElements) ---
let detectionStatusElement, detectionStatusText, startAnalysisButton;
let totalThreatsElement, unresolvedThreatsElement, criticalAlertsElement;
let systemStatusTextElement, cpuUsageElement, memoryUsageElement, networkUsageElement;
let recentAlertsTableBody;
let statusArea; // Để ẩn log debug

// --- Chart Variables ---
let threatTrendsChart = null;
let systemMetricsChart = null;
// Add new chart variables here if you create more charts e.g.
// let aptProtocolChart = null;

const MAX_METRIC_POINTS = 30; // Giới hạn số điểm dữ liệu hiển thị cho system metrics

// This function should be called AFTER the dashboard HTML is loaded
function initializeDashboardElements() {
    console.log("Attempting to initialize dashboard elements...");
    detectionStatusElement = document.getElementById('detectionStatus');
    if (detectionStatusElement) {
        detectionStatusText = detectionStatusElement.querySelector('.status-text');
    } else {
        console.warn("'detectionStatus' element not found on current page.");
    }

    startAnalysisButton = document.getElementById('startAnalysisButton');
    if (!startAnalysisButton) console.warn("'startAnalysisButton' not found.");

    const recentAlertsTable = document.getElementById('recentAlertsTable');
    if (recentAlertsTable) {
        recentAlertsTableBody = recentAlertsTable.getElementsByTagName('tbody')[0];
    } else {
        console.warn("'recentAlertsTable' not found.");
    }

    totalThreatsElement = document.getElementById('totalThreats');
    criticalAlertsElement = document.getElementById('criticalAlerts');
    unresolvedThreatsElement = document.getElementById('unresolvedThreats');
    systemStatusTextElement = document.getElementById('systemStatus');
    cpuUsageElement = document.getElementById('cpuUsage');
    memoryUsageElement = document.getElementById('memoryUsage');
    networkUsageElement = document.getElementById('networkUsage');
    statusArea = document.getElementById('statusArea');

    console.log("Dashboard elements initialization attempt complete.");
}

function addDashboardEventListeners() {
    if (startAnalysisButton) {
        // Simple way to avoid multiple listeners if this function is called again:
        // clone and replace the button.
        const newButton = startAnalysisButton.cloneNode(true);
        startAnalysisButton.parentNode.replaceChild(newButton, startAnalysisButton);
        startAnalysisButton = newButton; // Update reference

        startAnalysisButton.addEventListener('click', () => {
            console.log("Start Analysis button clicked!");
            if (detectionStatusText && detectionStatusElement) updateDetectionStatus(true, 'Starting...'); // Make sure element exists
            if (recentAlertsTableBody) clearTable(recentAlertsTableBody);

            if (window.electronAPI && typeof window.electronAPI.startAnalysis === 'function') {
                window.electronAPI.startAnalysis();
            } else {
                console.error("electronAPI.startAnalysis is not available.");
                // Provide feedback to user if API is not available
                if (detectionStatusText && detectionStatusElement) updateDetectionStatus(false, 'Error: API unavailable');
                return;
            }
            startAnalysisButton.disabled = true;
            startAnalysisButton.textContent = "Analysis Running...";
        });
        console.log("Event listener added to startAnalysisButton.");
    } else {
        console.warn("startAnalysisButton not found, cannot add event listener.");
    }
}


// --- IPC Handlers ---
if (window.electronAPI) {
    window.electronAPI.onStatusUpdate((message) => {
        console.log("Status Update:", message);
        if (statusArea) {
            statusArea.textContent += message + '\n';
            statusArea.scrollTop = statusArea.scrollHeight;
        }

        if (detectionStatusElement && detectionStatusText) { // Check elements exist
            if (message.includes("Starting Network Analysis Pipeline")) {
                updateDetectionStatus(true, 'Detection Active');
            } else if (message.includes("Network Analysis Pipeline Finished") || message.includes("LỖI")) {
                updateDetectionStatus(false, message.includes("LỖI") ? 'Error Occurred' : 'Detection Inactive');
                if (startAnalysisButton) {
                    startAnalysisButton.disabled = false;
                    startAnalysisButton.textContent = "Start Analysis";
                }
            } else if (message.includes("Starting Prediction Module")) {
                updateDetectionStatus(true, 'Analyzing...');
            }
        }
    });

    window.electronAPI.onClearResults(() => {
        if (recentAlertsTableBody) clearTable(recentAlertsTableBody);
        if (totalThreatsElement) totalThreatsElement.textContent = '0';
        if (criticalAlertsElement) criticalAlertsElement.textContent = '0';
        if (unresolvedThreatsElement) unresolvedThreatsElement.textContent = '0 unresolved threats';

        // Clear charts too
        if (document.getElementById('threatTrendsChart')) {
            updateThreatTrendsChart({ labels: [], critical: [], high: [], medium: [], low: [] });
        }
        // If you add more charts, clear them here e.g.
        // if (document.getElementById('aptProtocolChart')) {
        //    updateAptProtocolChart({ labels: [], data: [] });
        // }
    });

    window.electronAPI.onResultsData((data) => {
        console.log("Results Data Received:", data);

        const currentTotalThreats = document.getElementById('totalThreats');
        const currentCriticalAlerts = document.getElementById('criticalAlerts');
        const currentUnresolvedThreats = document.getElementById('unresolvedThreats');
        const currentRecentAlertsTableBody = document.getElementById('recentAlertsTable')?.getElementsByTagName('tbody')[0];
        const normalTraffic = document.getElementById('normalTraffic');
        const suspiciousTraffic = document.getElementById('suspiciousTraffic');
        const maliciousTraffic = document.getElementById('maliciousTraffic');
        const activeAttacks = document.getElementById('activeAttacks');
        const countries = document.getElementById('countries');
        const totalToday = document.getElementById('totalToday');

        if (currentTotalThreats) currentTotalThreats.textContent = data.totalThreats !== undefined ? data.totalThreats : 'N/A';
        if (currentCriticalAlerts) currentCriticalAlerts.textContent = data.criticalAlerts !== undefined ? data.criticalAlerts : 'N/A';
        if (currentUnresolvedThreats) currentUnresolvedThreats.textContent = `${data.unresolvedThreats || data.totalThreats || 0} total threats detected`;
        if (normalTraffic) normalTraffic.textContent = '1.423 GB'; // Example data
        if (suspiciousTraffic) suspiciousTraffic.textContent = '62 MB'; // Example data
        if (maliciousTraffic) maliciousTraffic.textContent = '12 MB'; // Example data
        if (activeAttacks) activeAttacks.textContent = '24'; // Example data
        if (countries) countries.textContent = '8'; // Example data
        if (totalToday) totalToday.textContent = '156'; // Example data

        if (currentRecentAlertsTableBody) updateRecentAlertsTable(data.suspicious, currentRecentAlertsTableBody);

        if (document.getElementById('threatTrendsChart')) {
            if (data.suspicious && Array.isArray(data.suspicious)) {
                const trendData = processCsvDataForThreatTrendsChart(data.suspicious);
                updateThreatTrendsChart(trendData);
            }
        }

        if (document.getElementById('trafficAnalysisChart') && trafficAnalysisChart) {
            // Update with sample data (replace with actual logic)
            trafficAnalysisChart.data.datasets[0].data = [100, 100, 100, 100, 120, 130, 140, 141, 142, 142, 142, 1423];
            trafficAnalysisChart.data.datasets[1].data = [0, 0, 0, 0, 5, 10, 15, 20, 25, 30, 40, 62];
            trafficAnalysisChart.data.datasets[2].data = [0, 0, 0, 0, 2, 4, 6, 8, 10, 11, 11, 12];
            trafficAnalysisChart.update();
        }

        if (detectionStatusElement && detectionStatusText) {
            updateDetectionStatus(false, 'Analysis Complete');
            if (startAnalysisButton) {
                startAnalysisButton.disabled = false;
                startAnalysisButton.textContent = "Start Analysis";
            }
        }
    });

    window.electronAPI.onSystemMetrics((metrics) => {
        // console.log("Received system metrics:", metrics);
        const sysStatTextEl = document.getElementById('systemStatus');
        const cpuUseEl = document.getElementById('cpuUsage');
        const memUseEl = document.getElementById('memoryUsage');
        const netUseEl = document.getElementById('networkUsage');

        if (sysStatTextEl) sysStatTextEl.textContent = "Active";
        if (cpuUseEl) cpuUseEl.textContent = metrics.cpu !== undefined ? `${metrics.cpu.toFixed(1)}%` : '--%';
        if (memUseEl) memUseEl.textContent = metrics.mem !== undefined ? `${metrics.mem.toFixed(1)}%` : '--%';
        if (netUseEl) netUseEl.textContent = metrics.net !== undefined ? `${(metrics.net / 1024).toFixed(1)} KB/s` : '-- KB/s';

        if (document.getElementById('systemMetricsChart')) {
            const netKBps = metrics.net !== undefined ? (metrics.net / 1024) : null;
            updateSystemMetricsChartWithAllMetrics(metrics.timestamp, metrics.cpu, metrics.mem, netKBps);
        }
    });

} else {
    console.error("window.electronAPI is not defined. IPC handlers will not be set up.");
}


// --- UI Update Functions ---
function updateDetectionStatus(isActive, text) {
    if (!detectionStatusElement || !detectionStatusText) { // Check if elements are available
        console.warn("Detection status elements not found, cannot update status.");
        return;
    }
    detectionStatusText.textContent = text;
    if (isActive) {
        detectionStatusElement.classList.remove('inactive');
        detectionStatusElement.classList.add('active');
    } else {
        detectionStatusElement.classList.remove('active');
        detectionStatusElement.classList.add('inactive');
    }
}

function clearTable(tbody) {
    if (!tbody) return;
    tbody.innerHTML = '';
}

function updateRecentAlertsTable(alerts, tableBody) { // Pass tableBody as argument
    if (!tableBody) {
        console.warn("Recent alerts table body not found, cannot update.");
        return;
    }
    clearTable(tableBody);

    if (!alerts || alerts.length === 0) {
        const row = tableBody.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6; // Adjust to your table's column count
        cell.textContent = 'No suspicious activities detected.';
        cell.style.textAlign = 'center';
        cell.style.color = 'var(--text-muted)';
        return;
    }

    const alertsToShow = alerts.slice(0, 10); // Show top 10

    alertsToShow.forEach(alert => {
        const row = tableBody.insertRow();
        const severityDetails = getSeverityDetailsFromAlert(alert); // Use helper for severity

        row.insertCell().innerHTML = `<span class="severity-badge ${severityDetails.class}">${severityDetails.text}</span>`;
        row.insertCell().textContent = alert.Prediction || 'N/A';
        row.insertCell().textContent = alert['Src IP'] || alert['Source IP'] || 'N/A';
        row.insertCell().textContent = alert['Dst IP'] || alert['Destination IP'] || 'N/A';
        row.insertCell().textContent = alert.Timestamp ? new Date(alert.Timestamp).toLocaleString() : 'N/A';
        row.insertCell().innerHTML = `<a href="#" class="details-link" data-flowid="${alert['Flow ID'] || ''}">Details</a>`;
    });
}

// Helper function to determine severity text and class from an alert object
function getSeverityDetailsFromAlert(alert) {
    let severityText = 'Low';
    let severityClass = 'severity-low';
    const prediction = alert.Prediction ? String(alert.Prediction).toLowerCase() : '';
    // Assuming Prediction_Probability is a field in your CSV data (0.0 to 1.0)
    const probability = typeof alert.Prediction_Probability === 'number' ? alert.Prediction_Probability : 0;

    // Customize this logic based on your specific prediction values and probability thresholds
    // This is just an example matching your original table logic
    if (prediction.includes('critical') || (prediction !== 'benign' && probability > 0.9)) {
        severityText = 'Critical';
        severityClass = 'severity-critical';
    } else if (prediction.includes('high') || (prediction !== 'benign' && probability > 0.7)) {
        severityText = 'High';
        severityClass = 'severity-high';
    } else if (prediction.includes('medium') || (prediction !== 'benign' && probability > 0.5)) {
        severityText = 'Medium';
        severityClass = 'severity-medium';
    } else if (prediction === 'benign' || prediction === '') {
        // For benign or unclassified that doesn't meet other criteria.
        // You might want a different handling for benign, e.g., not showing in "threats" table
        // or a specific "Informational" severity.
        severityText = 'Info'; // Or keep 'Low' if all non-benign start as Low
        severityClass = 'severity-info'; // Or 'severity-low'
    }
    // If it's not benign and didn't match higher severities, it defaults to Low.

    return { text: severityText, class: severityClass, level: severityText }; // level can be used for aggregation
}


// --- Chart Functions ---
// Add new chart variable
let trafficAnalysisChart = null;

// Update initializeOrReinitializeCharts function
function initializeOrReinitializeCharts() {
    destroyCharts();

    // Existing Threat Trends Chart
    const ctxTrendsElement = document.getElementById('threatTrendsChart');
    if (ctxTrendsElement) {
        const ctxTrends = ctxTrendsElement.getContext('2d');
        threatTrendsChart = new Chart(ctxTrends, {
            type: 'bar',
            data: {
                labels: [], // e.g., Dates or time periods
                datasets: [
                    { label: 'Critical', data: [], backgroundColor: 'var(--critical-color, #dc3545)', stack: 'Severity' },
                    { label: 'High', data: [], backgroundColor: 'var(--high-color, #fd7e14)', stack: 'Severity' },
                    { label: 'Medium', data: [], backgroundColor: 'var(--medium-color, #ffc107)', stack: 'Severity' },
                    { label: 'Low', data: [], backgroundColor: 'var(--low-color, #17a2b8)', stack: 'Severity' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { color: 'var(--text-muted, #6c757d)' } },
                    title: { display: true, text: 'Threat Detections Over Time', color: 'var(--text-primary, #333)' }
                },
                scales: {
                    x: { stacked: true, ticks: { color: 'var(--text-muted, #6c757d)' }, grid: { color: 'var(--border-color, #dee2e6)' } },
                    y: { stacked: true, ticks: { color: 'var(--text-muted, #6c757d)' }, grid: { color: 'var(--border-color, #dee2e6)' }, beginAtZero: true }
                }
            }
        });
        console.log("Threat Trends Chart initialized.");
    }

    // Existing System Metrics Chart
    const ctxMetricsElement = document.getElementById('systemMetricsChart');
    if (ctxMetricsElement) {
        const ctxMetrics = ctxMetricsElement.getContext('2d');
        systemMetricsChart = new Chart(ctxMetrics, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'CPU Usage (%)', data: [], borderColor: 'var(--cpu-color, rgba(255, 99, 132, 1))', backgroundColor: 'var(--cpu-bg-color, rgba(255, 99, 132, 0.2))', fill: true, tension: 0.1 },
                    { label: 'Memory Usage (%)', data: [], borderColor: 'var(--mem-color, rgba(54, 162, 235, 1))', backgroundColor: 'var(--mem-bg-color, rgba(54, 162, 235, 0.2))', fill: true, tension: 0.1 },
                    { label: 'Network Usage (KB/s)', data: [], borderColor: 'var(--net-color, rgba(75, 192, 192, 1))', backgroundColor: 'var(--net-bg-color, rgba(75, 192, 192, 0.2))', fill: true, tension: 0.1 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { color: 'var(--text-muted, #6c757d)' } },
                    title: { display: true, text: 'System Resource Usage', color: 'var(--text-primary, #333)' }
                },
                scales: {
                    x: { ticks: { color: 'var(--text-muted, #6c757d)' }, grid: { color: 'var(--border-color, #dee2e6)' } },
                    y: { ticks: { color: 'var(--text-muted, #6c757d)' }, grid: { color: 'var(--border-color, #dee2e6)' }, beginAtZero: true, suggestedMax: 100 }
                }
            }
        });
        console.log("System Metrics Chart initialized.");
    }

    // New Traffic Analysis Chart
    const ctxTrafficElement = document.getElementById('trafficAnalysisChart');
    if (ctxTrafficElement) {
        const ctxTraffic = ctxTrafficElement.getContext('2d');
        trafficAnalysisChart = new Chart(ctxTraffic, {
            type: 'bar',
            data: {
                labels: ['00:00', '01:00', '02:00', '03:00', '04:00', '05:00', '06:00', '07:00', '08:00', '09:00', '10:00', '11:00'],
                datasets: [
                    { label: 'Normal', data: [100, 100, 100, 100, 120, 130, 140, 141, 142, 142, 142, 1423], backgroundColor: '#4caf50', stack: 'Traffic' },
                    { label: 'Suspicious', data: [0, 0, 0, 0, 5, 10, 15, 20, 25, 30, 40, 62], backgroundColor: '#ffc107', stack: 'Traffic' },
                    { label: 'Malicious', data: [0, 0, 0, 0, 2, 4, 6, 8, 10, 11, 11, 12], backgroundColor: '#dc3545', stack: 'Traffic' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { color: 'var(--text-muted, #6c757d)' } },
                    title: { display: true, text: 'Traffic Analysis', color: 'var(--text-primary, #333)' }
                },
                scales: {
                    x: { stacked: true, ticks: { color: 'var(--text-muted, #6c757d)' }, grid: { color: 'var(--border-color, #dee2e6)' } },
                    y: { stacked: true, ticks: { color: 'var(--text-muted, #6c757d)' }, grid: { color: 'var(--border-color, #dee2e6)' }, beginAtZero: true }
                }
            }
        });
        console.log("Traffic Analysis Chart initialized.");
    }
}
// Update destroyCharts to include trafficAnalysisChart
function destroyCharts() {
    if (threatTrendsChart) {
        threatTrendsChart.destroy();
        threatTrendsChart = null;
    }
    if (systemMetricsChart) {
        systemMetricsChart.destroy();
        systemMetricsChart = null;
    }
    if (trafficAnalysisChart) {
        trafficAnalysisChart.destroy();
        trafficAnalysisChart = null;
    }
}
/**
 * Processes raw CSV data to aggregate threat counts by severity over time periods.
 * @param {Array<Object>} csvRows - Array of objects, where each object is a row from the CSV.
 * Each row must have 'Timestamp' and other features needed for severity.
 * @param {string} timeWindow - 'daily', 'hourly' (currently only 'daily' implemented).
 * @returns {Object} - { labels: [], critical: [], high: [], medium: [], low: [] }
 */
function processCsvDataForThreatTrendsChart(csvRows, timeWindow = 'daily') {
    if (!csvRows || csvRows.length === 0) {
        return { labels: [], critical: [], high: [], medium: [], low: [] };
    }

    const aggregatedData = {}; // Key: YYYY-MM-DD (for daily), Value: { Critical: 0, High: 0, ... }

    csvRows.forEach(row => {
        if (!row.Timestamp) {
            console.warn("CSV row missing Timestamp:", row);
            return; // Skip if no timestamp
        }

        const severityDetails = getSeverityDetailsFromAlert(row); // Use the helper
        if (severityDetails.level === 'Info' || !severityDetails.level) { // Don't count 'Info' or unclassified in threat trends
            return;
        }

        let dateKey;
        try {
            const timestamp = new Date(row.Timestamp);
            if (isNaN(timestamp.getTime())) { // Check for invalid date
                console.warn("Invalid timestamp in CSV row:", row.Timestamp, row);
                return;
            }
            // For daily aggregation
            dateKey = timestamp.toISOString().split('T')[0]; // YYYY-MM-DD
            // TODO: Implement hourly or other timeWindows if needed
        } catch (e) {
            console.warn("Error parsing timestamp from CSV row:", row.Timestamp, e);
            return;
        }


        if (!aggregatedData[dateKey]) {
            aggregatedData[dateKey] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        }
        if (aggregatedData[dateKey][severityDetails.level] !== undefined) {
            aggregatedData[dateKey][severityDetails.level]++;
        }
    });

    const sortedDates = Object.keys(aggregatedData).sort((a, b) => new Date(a) - new Date(b));

    const labels = [];
    const criticalData = [];
    const highData = [];
    const mediumData = [];
    const lowData = [];

    // To ensure a continuous range (e.g., last 30 days), you might want to generate all labels in that range
    // and then fill in data. For now, just using dates present in the data.
    // Example: Get range from first to last detected date, or a fixed window like last 7 days.
    // For simplicity, this version uses only dates with data.

    sortedDates.forEach(date => {
        labels.push(date);
        criticalData.push(aggregatedData[date].Critical);
        highData.push(aggregatedData[date].High);
        mediumData.push(aggregatedData[date].Medium);
        lowData.push(aggregatedData[date].Low);
    });

    return {
        labels: labels,
        critical: criticalData,
        high: highData,
        medium: mediumData,
        low: lowData
    };
}


function updateThreatTrendsChart(processedTrendData) {
    if (!threatTrendsChart || !document.getElementById('threatTrendsChart')) {
        // console.warn("Threat trends chart not initialized or canvas not found. Cannot update.");
        return;
    }
    if (!processedTrendData) {
        console.warn("No processed trend data to update chart.");
        return;
    }
    threatTrendsChart.data.labels = processedTrendData.labels;
    threatTrendsChart.data.datasets[0].data = processedTrendData.critical;
    threatTrendsChart.data.datasets[1].data = processedTrendData.high;
    threatTrendsChart.data.datasets[2].data = processedTrendData.medium;
    threatTrendsChart.data.datasets[3].data = processedTrendData.low;
    threatTrendsChart.update();
    console.log("Threat Trends Chart updated.");
}


function updateSystemMetricsChartWithAllMetrics(timestamp, cpu, mem, net) {
    if (!systemMetricsChart || !document.getElementById('systemMetricsChart')) {
        // console.warn("System metrics chart not initialized or canvas not found. Cannot update.");
        return;
    }

    const label = new Date(timestamp || Date.now()).toLocaleTimeString();

    systemMetricsChart.data.labels.push(label);
    systemMetricsChart.data.datasets[0].data.push(cpu !== undefined && cpu !== null ? cpu : 0);
    systemMetricsChart.data.datasets[1].data.push(mem !== undefined && mem !== null ? mem : 0);
    systemMetricsChart.data.datasets[2].data.push(net !== undefined && net !== null ? net : 0);


    if (systemMetricsChart.data.labels.length > MAX_METRIC_POINTS) {
        systemMetricsChart.data.labels.shift();
        systemMetricsChart.data.datasets.forEach(dataset => dataset.data.shift());
    }
    systemMetricsChart.update('none'); // 'none' for no animation, good for real-time updates
    // console.log("System Metrics Chart updated.");
}


// --- Window Control Event Listeners (assuming these are in your main HTML file or loaded with dashboard) ---
// It's generally better to add these listeners once the main shell of the app is loaded,
// rather than re-adding them every time 'dashboard' is loaded.
// If they are part of the persistent UI (e.g. a top bar):
document.addEventListener('DOMContentLoaded', () => { // Or ensure these are only run once
    const minimizeBtn = document.getElementById('minimize-btn');
    const maximizeRestoreBtn = document.getElementById('maximize-restore-btn');
    const closeBtn = document.getElementById('close-btn');
    const maximizeIcon = document.getElementById('maximize-icon');
    const restoreIcon = document.getElementById('restore-icon');

    if (minimizeBtn && window.electronAPI) {
        minimizeBtn.addEventListener('click', () => window.electronAPI.minimizeApp());
    }
    if (maximizeRestoreBtn && window.electronAPI) {
        maximizeRestoreBtn.addEventListener('click', () => window.electronAPI.maximizeRestoreApp());
    }
    if (closeBtn && window.electronAPI) {
        closeBtn.addEventListener('click', () => window.electronAPI.closeApp());
    }

    if (window.electronAPI && typeof window.electronAPI.onWindowMaximized === 'function') {
        window.electronAPI.onWindowMaximized(() => {
            if (maximizeIcon) maximizeIcon.style.display = 'none';
            if (restoreIcon) restoreIcon.style.display = 'block';
            if (maximizeRestoreBtn) maximizeRestoreBtn.title = 'Restore';
        });
    }
    if (window.electronAPI && typeof window.electronAPI.onWindowUnmaximized === 'function') {
        window.electronAPI.onWindowUnmaximized(() => {
            if (maximizeIcon) maximizeIcon.style.display = 'block';
            if (restoreIcon) restoreIcon.style.display = 'none';
            if (maximizeRestoreBtn) maximizeRestoreBtn.title = 'Maximize';
        });
    }
});