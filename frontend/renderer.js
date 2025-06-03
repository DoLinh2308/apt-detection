// frontend/renderer.js

// --- GLOBAL CONFIG & UTILITIES ---
const MAX_SYSTEM_METRIC_POINTS = 30; // Max data points for system metrics chart

// --- DOM Element References (sẽ được khởi tạo trong các hàm page-specific) ---
let statusArea; // Log debug
// Dashboard elements
let detectionStatusElement, detectionStatusText, startAnalysisButton, stopAnalysisButton;
let totalThreatsElement, unresolvedThreatsElement, criticalAlertsElement;
let systemStatusTextElement, cpuUsageElement, memoryUsageElement, networkUsageElement;
let recentAlertsTableBody;

// --- NAVIGATION & PAGE LOADING ---
const Navigation = {
    contentArea: null,
    navLinks: {},
    activePage: null,

    init: function () {
        this.contentArea = document.getElementById('main-content');
        this.navLinks = {
            dashboard: document.getElementById('nav-dashboard'),
            alert: document.getElementById('nav-alert'),
            network: document.getElementById('nav-network'),
            log: document.getElementById('nav-log'),
            setting: document.getElementById('nav-setting')
        };

        for (const pageName in this.navLinks) {
            if (this.navLinks[pageName]) {
                this.navLinks[pageName].addEventListener('click', (e) => {
                    e.preventDefault();
                    this.loadPage(pageName);
                });
            }
        }
    },

    loadPage: async function (pageName) {
        if (!this.contentArea) {
            console.error("Content area not initialized for navigation.");
            return;
        }
        try {
            console.log(`Loading page: ${pageName}`);
            const response = await fetch(`${pageName}.html`);
            if (!response.ok) {
                this.contentArea.innerHTML = `<p>Error: Could not load ${pageName}.html. Status: ${response.status}</p>`;
                console.error(`Failed to load ${pageName}.html: ${response.status}`);
                return;
            }
            const htmlContent = await response.text();
            this.contentArea.innerHTML = htmlContent;
            this.updateActiveLink(pageName);
            this.activePage = pageName;

            // Call page-specific initializers
            if (pageName === 'dashboard') {
                PageInitializers.dashboard();
            } else if (pageName === 'setting') {
                PageInitializers.setting();
            }
            // Re-apply theme after loading new content, especially if charts are involved
            ThemeManager.applyCurrentTheme();

        } catch (error) {
            console.error(`Error loading page ${pageName}:`, error);
            this.contentArea.innerHTML = `<p>Error loading page: ${error.message}</p>`;
        }
    },

    updateActiveLink: function (activePage) {
        for (const id in this.navLinks) {
            if (this.navLinks[id]) {
                this.navLinks[id].classList.remove('active');
            }
        }
        if (this.navLinks[activePage]) {
            this.navLinks[activePage].classList.add('active');
        }
    }
};

// --- THEME MANAGEMENT ---
const ThemeManager = {
    currentTheme: 'dark', // Default theme

    applyTheme: function (themeName) {
        document.body.classList.remove('light-theme', 'dark-theme');
        if (themeName === 'light') {
            document.body.classList.add('light-theme');
        } else {
            document.body.classList.add('dark-theme');
        }
        this.currentTheme = themeName;
        console.log(`Theme applied: ${themeName}`);

        if (Navigation.activePage === 'dashboard' && ChartManager.areChartsInitialized()) {
            console.log("Reinitializing charts for new theme...");
            ChartManager.initializeAllCharts();
        }
    },

    applyCurrentTheme: function () {
        this.applyTheme(this.currentTheme);
    },

    loadAndApplySavedTheme: async function () {
        if (window.electronAPI && typeof window.electronAPI.loadSettings === 'function') {
            try {
                const settings = await window.electronAPI.loadSettings();
                if (settings && settings.theme) {
                    this.applyTheme(settings.theme);
                } else {
                    this.applyTheme('dark'); // Default
                }
            } catch (error) {
                console.error("Failed to load settings for theme:", error);
                this.applyTheme('dark'); // Default on error
            }
        } else {
            this.applyTheme('dark'); // Default if API not ready
        }
    },

    updateThemeSelectElement: function () {
        const themeSelectElement = document.getElementById('theme-select');
        if (themeSelectElement) {
            themeSelectElement.value = this.currentTheme;
        }
    }
};

// --- CHART MANAGEMENT ---
const ChartManager = {
    charts: {
        threatTrends: null,
        systemMetrics: null,
        trafficAnalysis: null,
        aptTypeDistribution: null,
        topAptSourceIp: null,
        topAptDestIp: null,
        aptProtocol: null
    },

    areChartsInitialized: function () {
        return !!document.getElementById('threatTrendsChart'); // Check one prominent chart
    },

    initializeAllCharts: function () {
        console.log("Attempting to initialize all charts...");
        this.destroyAllCharts();

        const ctxTrends = document.getElementById('threatTrendsChart')?.getContext('2d');
        if (ctxTrends) {
            this.charts.threatTrends = new Chart(ctxTrends, {
                type: 'bar',
                data: {
                    labels: [], datasets: [
                        { label: 'Critical', data: [], backgroundColor: 'var(--critical-color)', stack: 'Severity' },
                        { label: 'High', data: [], backgroundColor: 'var(--high-color)', stack: 'Severity' },
                        { label: 'Medium', data: [], backgroundColor: 'var(--medium-color)', stack: 'Severity' },
                        { label: 'Low', data: [], backgroundColor: 'var(--low-color)', stack: 'Severity' }
                    ]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top', labels: { color: 'var(--text-secondary)' } }, title: { display: true, text: 'Threat Detections Over Time', color: 'var(--text-primary)' } }, scales: { x: { stacked: true, ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } }, y: { stacked: true, ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' }, beginAtZero: true } } }
            });
            console.log("Threat Trends Chart initialized.");
        }

        const ctxMetrics = document.getElementById('systemMetricsChart')?.getContext('2d');
        if (ctxMetrics) {
            this.charts.systemMetrics = new Chart(ctxMetrics, {
                type: 'line',
                data: {
                    labels: [], datasets: [
                        { label: 'CPU Usage (%)', data: [], borderColor: 'var(--cpu-color)', backgroundColor: 'var(--cpu-bg-color)', fill: true, tension: 0.1 },
                        { label: 'Memory Usage (%)', data: [], borderColor: 'var(--mem-color)', backgroundColor: 'var(--mem-bg-color)', fill: true, tension: 0.1 },
                        { label: 'Network Usage (KB/s)', data: [], borderColor: 'var(--net-color)', backgroundColor: 'var(--net-bg-color)', fill: true, tension: 0.1 }
                    ]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top', labels: { color: 'var(--text-secondary)' } }, title: { display: true, text: 'System Resource Usage', color: 'var(--text-primary)' } }, scales: { x: { ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } }, y: { ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' }, beginAtZero: true, suggestedMax: 100 } } }
            });
            console.log("System Metrics Chart initialized.");
        }

        const ctxTraffic = document.getElementById('trafficAnalysisChart')?.getContext('2d');
        if (ctxTraffic) {
            this.charts.trafficAnalysis = new Chart(ctxTraffic, {
                type: 'bar',
                data: {
                    labels: [], datasets: [
                        { label: 'Lưu lượng Bình thường', data: [], backgroundColor: 'rgba(75, 192, 192, 0.7)', stack: 'scanData' },
                        { label: 'Lưu lượng Nghi ngờ', data: [], backgroundColor: 'rgba(255, 206, 86, 0.7)', stack: 'scanData' },
                        { label: 'Lưu lượng Độc hại', data: [], backgroundColor: 'rgba(255, 99, 132, 0.7)', stack: 'scanData' }
                    ]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top', labels: { color: 'var(--text-secondary)' } }, title: { display: true, text: 'Thống Kê Lưu Lượng Qua Các Lần Quét', color: 'var(--text-primary)' } }, scales: { x: { title: { display: true, text: 'Lần Quét', color: 'var(--text-secondary)' }, ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } }, y: { title: { display: true, text: 'Dung lượng (Units)', color: 'var(--text-secondary)' }, beginAtZero: true, ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } } } }
            });
            console.log("Traffic Analysis Chart (by Scan) initialized.");
        }

        const ctxAptType = document.getElementById('aptTypeDistributionChart')?.getContext('2d');
        if (ctxAptType) {
            this.charts.aptTypeDistribution = new Chart(ctxAptType, {
                type: 'doughnut',
                data: { labels: [], datasets: [{ label: 'Số lượng', data: [], backgroundColor: ['rgba(255, 99, 132, 0.7)', 'rgba(54, 162, 235, 0.7)', 'rgba(255, 206, 86, 0.7)', 'rgba(75, 192, 192, 0.7)', 'rgba(153, 102, 255, 0.7)', 'rgba(255, 159, 64, 0.7)'], borderColor: 'var(--background-content)', borderWidth: 2 }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top', labels: { color: 'var(--text-secondary)' } }, title: { display: true, text: 'Phân bố Loại Tấn Công APT', color: 'var(--text-primary)' } } }
            });
            console.log("APT Type Distribution Chart initialized.");
        }

        const ctxTopSrcIp = document.getElementById('topAptSourceIpChart')?.getContext('2d');
        if (ctxTopSrcIp) {
            this.charts.topAptSourceIp = new Chart(ctxTopSrcIp, {
                type: 'bar',
                data: { labels: [], datasets: [{ label: 'Số Lần Ghi Nhận', data: [], backgroundColor: 'rgba(75, 192, 192, 0.7)' }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: 'Top IP Nguồn Tấn Công APT', color: 'var(--text-primary)' } }, scales: { x: { beginAtZero: true, ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } }, y: { ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } } } }
            });
            console.log("Top APT Source IP Chart initialized.");
        }
        const ctxTopDestIp = document.getElementById('topAptDestIpChart')?.getContext('2d');
        if (ctxTopDestIp) {
            this.charts.topAptDestIp = new Chart(ctxTopDestIp, {
                type: 'bar',
                data: { labels: [], datasets: [{ label: 'Số Lần Ghi Nhận', data: [], backgroundColor: 'rgba(255, 159, 64, 0.7)' }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: 'Top IP Đích Bị Tấn Công APT', color: 'var(--text-primary)' } }, scales: { x: { beginAtZero: true, ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } }, y: { ticks: { color: 'var(--text-secondary)' }, grid: { color: 'var(--border-color)' } } } }
            });
            console.log("Top APT Destination IP Chart initialized.");
        }
        const ctxAptProto = document.getElementById('aptProtocolChart')?.getContext('2d');
        if (ctxAptProto) {
            this.charts.aptProtocol = new Chart(ctxAptProto, {
                type: 'pie',
                data: { labels: [], datasets: [{ label: 'Số lượng', data: [], backgroundColor: ['rgba(153, 102, 255, 0.7)', 'rgba(255, 159, 64, 0.7)', 'rgba(201, 203, 207, 0.7)', 'rgba(54, 162, 235, 0.7)'], borderColor: 'var(--background-content)', borderWidth: 2 }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top', labels: { color: 'var(--text-secondary)' } }, title: { display: true, text: 'Phân bố Giao thức Tấn Công APT', color: 'var(--text-primary)' } } }
            });
            console.log("APT Protocol Chart initialized.");
        }
    },

    destroyAllCharts: function () {
        for (const chartKey in this.charts) {
            if (this.charts[chartKey]) {
                this.charts[chartKey].destroy();
                this.charts[chartKey] = null;
            }
        }
        console.log("All charts destroyed.");
    },

    updateThreatTrends: function (processedTrendData) {
        const chart = this.charts.threatTrends;
        if (chart && document.getElementById('threatTrendsChart')) {
            chart.data.labels = processedTrendData.labels || [];
            chart.data.datasets[0].data = processedTrendData.critical || [];
            chart.data.datasets[1].data = processedTrendData.high || [];
            chart.data.datasets[2].data = processedTrendData.medium || [];
            chart.data.datasets[3].data = processedTrendData.low || [];
            chart.update();
            console.log("Threat Trends Chart updated.");
        }
    },

    updateSystemMetrics: function (timestamp, cpu, mem, net) {
        const chart = this.charts.systemMetrics;
        if (chart && document.getElementById('systemMetricsChart')) {
            const label = new Date(timestamp || Date.now()).toLocaleTimeString();
            chart.data.labels.push(label);
            chart.data.datasets[0].data.push(cpu !== undefined && cpu !== null ? cpu : 0);
            chart.data.datasets[1].data.push(mem !== undefined && mem !== null ? mem : 0);
            chart.data.datasets[2].data.push(net !== undefined && net !== null ? net : 0);

            if (chart.data.labels.length > MAX_SYSTEM_METRIC_POINTS) {
                chart.data.labels.shift();
                chart.data.datasets.forEach(dataset => dataset.data.shift());
            }
            chart.update('none'); // 'none' for no animation, smoother updates
        }
    },
    updateTrafficAnalysis: function (scanHistory) {
        const chart = this.charts.trafficAnalysis;
        if (chart && document.getElementById('trafficAnalysisChart')) {
            if (!scanHistory || scanHistory.length === 0) {
                chart.data.labels = [];
                chart.data.datasets[0].data = [];
                chart.data.datasets[1].data = [];
                chart.data.datasets[2].data = [];
            } else {
                chart.data.labels = scanHistory.map((scan) => {
                    const date = new Date(scan.timestamp);
                    return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
                });
                chart.data.datasets[0].data = scanHistory.map(scan => scan.normal);
                chart.data.datasets[1].data = scanHistory.map(scan => scan.suspicious);
                chart.data.datasets[2].data = scanHistory.map(scan => scan.malicious);
            }
            chart.update();
            console.log("Traffic Analysis Chart (by Scan) updated.");
        }
    },
    updateAptTypeDistribution: function (counts) {
        const chart = this.charts.aptTypeDistribution;
        if (chart && document.getElementById('aptTypeDistributionChart')) {
            chart.data.labels = Object.keys(counts || {});
            chart.data.datasets[0].data = Object.values(counts || {});
            chart.update();
        }
    },
    updateTopIpChart: function (chartInstanceKey, ipCounts) {
        const chart = this.charts[chartInstanceKey];
        const canvasId = chartInstanceKey === 'topAptSourceIp' ? 'topAptSourceIpChart' : 'topAptDestIpChart';
        if (chart && document.getElementById(canvasId)) {
            chart.data.labels = Object.keys(ipCounts || {});
            chart.data.datasets[0].data = Object.values(ipCounts || {});
            chart.update();
        }
    },
    updateAptProtocol: function (counts) {
        const chart = this.charts.aptProtocol;
        if (chart && document.getElementById('aptProtocolChart')) {
            chart.data.labels = Object.keys(counts || {});
            chart.data.datasets[0].data = Object.values(counts || {});
            chart.update();
        }
    },
    clearAllChartData: function () {
        this.updateThreatTrends({ labels: [], critical: [], high: [], medium: [], low: [] });
        if (this.charts.systemMetrics) {
            this.charts.systemMetrics.data.labels = [];
            this.charts.systemMetrics.data.datasets.forEach(dataset => dataset.data = []);
            this.charts.systemMetrics.update();
        }
        // Don't clear scanHistory (trafficAnalysis) by default on 'clear-results',
        // it's persistent historical data. It will update with new scan data.
        this.updateAptTypeDistribution({});
        this.updateTopIpChart('topAptSourceIp', {});
        this.updateTopIpChart('topAptDestIp', {});
        this.updateAptProtocol({});
        console.log("Cleared data for relevant charts (excluding scan history).");
    }
};

// --- PAGE SPECIFIC INITIALIZERS & EVENT LISTENERS ---
const PageInitializers = {
    _getClonedButton: function (buttonId) {
        const originalButton = document.getElementById(buttonId);
        if (!originalButton) {
            console.warn(`Button with id '${buttonId}' not found.`);
            return null;
        }
        // Clone and replace to remove old event listeners effectively
        const clonedButton = originalButton.cloneNode(true);
        originalButton.parentNode.replaceChild(clonedButton, originalButton);
        return clonedButton;
    },

    dashboard: function () {
        console.log("Initializing dashboard elements and listeners...");
        detectionStatusElement = document.getElementById('detectionStatus');
        if (detectionStatusElement) detectionStatusText = detectionStatusElement.querySelector('.status-text');
        startAnalysisButton = this._getClonedButton('startAnalysisButton');
        stopAnalysisButton = this._getClonedButton('stopAnalysisButton');
        totalThreatsElement = document.getElementById('totalThreats');
        unresolvedThreatsElement = document.getElementById('unresolvedThreats');
        criticalAlertsElement = document.getElementById('criticalAlerts');
        systemStatusTextElement = document.getElementById('systemStatus');
        cpuUsageElement = document.getElementById('cpuUsage');
        memoryUsageElement = document.getElementById('memoryUsage');
        networkUsageElement = document.getElementById('networkUsage');
        const recentAlertsTable = document.getElementById('recentAlertsTable');
        if (recentAlertsTable) recentAlertsTableBody = recentAlertsTable.getElementsByTagName('tbody')[0];
        statusArea = document.getElementById('statusArea');

        ChartManager.initializeAllCharts();

        if (startAnalysisButton) {
            startAnalysisButton.addEventListener('click', () => {
                UIUpdater.updateDetectionStatus(null, 'Starting...');
                if (recentAlertsTableBody) UIUpdater.clearTable(recentAlertsTableBody);
                ChartManager.clearAllChartData(); // Clear previous non-historical results visuals

                if (window.electronAPI) window.electronAPI.startAnalysis();
                startAnalysisButton.disabled = true;
                startAnalysisButton.textContent = "Analysis Running...";
                if (stopAnalysisButton) stopAnalysisButton.disabled = false;
            });
        }
        if (stopAnalysisButton) {
            stopAnalysisButton.disabled = true;
            stopAnalysisButton.addEventListener('click', () => {
                if (window.electronAPI) {
                    window.electronAPI.stopAnalysis();
                    UIUpdater.updateDetectionStatus(false, 'Stopping...');
                    stopAnalysisButton.disabled = true;
                }
            });
        }
        // Load initial scan history
        if (IPCManager.initialSettingsData && IPCManager.initialSettingsData.scanHistory) {
            ChartManager.updateTrafficAnalysis(IPCManager.initialSettingsData.scanHistory);
        }
    },

    setting: function () {
        console.log("Initializing setting page elements and listeners...");
        ThemeManager.updateThemeSelectElement(); // Set theme dropdown

        const saveSettingsButton = this._getClonedButton('saveSettingsButton');
        const themeSelectElement = document.getElementById('theme-select');
        // Email settings fields
        const enableEmailNotif = document.getElementById('enable-email-notifications');
        const emailSenderAddr = document.getElementById('email-sender-address');
        const emailSenderPass = document.getElementById('email-sender-password');
        const emailReceiverAddr = document.getElementById('email-receiver-address');
        const emailSmtpServer = document.getElementById('email-smtp-server');
        const emailSmtpPort = document.getElementById('email-smtp-port');
        // Telegram settings fields
        const enableTelegramNotif = document.getElementById('enable-telegram-notifications');
        const telegramBotToken = document.getElementById('telegram-bot-token');
        const telegramChatId = document.getElementById('telegram-chat-id');

        // Load existing settings into fields
        if (window.electronAPI && typeof window.electronAPI.loadSettings === 'function') {
            window.electronAPI.loadSettings().then(settings => {
                console.log("Renderer received settings for form:", settings); // Log để xem settings nhận được là gì
                if (settings) {
                    if (themeSelectElement) themeSelectElement.value = settings.theme || 'dark';

                    // Email
                    if (enableEmailNotif) enableEmailNotif.checked = !!settings.enableEmailNotifications;
                    if (emailSenderAddr) emailSenderAddr.value = settings.emailSenderAddress || '';
                    // KHÔNG ĐIỀN LẠI MẬT KHẨU HOẶC TOKEN
                    // if (emailSenderPass) emailSenderPass.value = settings.emailSenderPassword || ''; // KHÔNG LÀM ĐIỀU NÀY
                    if (emailReceiverAddr) emailReceiverAddr.value = settings.emailReceiverAddress || '';
                    if (emailSmtpServer) emailSmtpServer.value = settings.emailSmtpServer || 'smtp.gmail.com';
                    if (emailSmtpPort) emailSmtpPort.value = settings.emailSmtpPort || 587;

                    // Telegram
                    if (enableTelegramNotif) enableTelegramNotif.checked = !!settings.enableTelegramNotifications;
                    // if (telegramBotToken) telegramBotToken.value = settings.telegramBotToken || ''; // KHÔNG LÀM ĐIỀU NÀY
                    if (telegramChatId) telegramChatId.value = settings.telegramChatId || '';
                }
            }).catch(err => console.error("Error loading settings for settings page form:", err));
        }


        if (saveSettingsButton) {
            saveSettingsButton.addEventListener('click', () => {
                const settingsToSave = {
                    theme: themeSelectElement ? themeSelectElement.value : 'dark',
                    enableEmailNotifications: enableEmailNotif ? enableEmailNotif.checked : false,
                    emailSenderAddress: emailSenderAddr ? emailSenderAddr.value : '',
                    emailSenderPassword: emailSenderPass ? emailSenderPass.value : '', // Store if provided
                    emailReceiverAddress: emailReceiverAddr ? emailReceiverAddr.value : '',
                    emailSmtpServer: emailSmtpServer ? emailSmtpServer.value : '',
                    emailSmtpPort: emailSmtpPort ? emailSmtpPort.value : '',
                    enableTelegramNotifications: enableTelegramNotif ? enableTelegramNotif.checked : false,
                    telegramBotToken: telegramBotToken ? telegramBotToken.value : '',
                    telegramChatId: telegramChatId ? telegramChatId.value : ''
                };

                console.log("Saving settings:", settingsToSave);
                // Clear password field after attempting to save for some basic security
                if (emailSenderPass) emailSenderPass.value = '';

                if (window.electronAPI) {
                    window.electronAPI.saveSettings(settingsToSave);
                    ThemeManager.applyTheme(settingsToSave.theme);
                    alert('Cài đặt đã được lưu! Mật khẩu Email (nếu được cung cấp) sẽ được sử dụng bởi hệ thống nhưng không được hiển thị lại tại đây.');
                } else {
                    alert('Lỗi: Không thể lưu cài đặt.');
                }
            });
        }
    }
};

// --- UI UPDATE UTILITIES ---
const UIUpdater = {
    updateDetectionStatus: function (isActive, text) {
        if (!detectionStatusElement || !detectionStatusText) { return; }
        detectionStatusText.textContent = text;
        const classes = detectionStatusElement.classList;
        classes.remove('active', 'inactive', 'analyzing');
        if (isActive === null) { classes.add('analyzing'); }
        else if (isActive) { classes.add('active'); }
        else { classes.add('inactive'); }
    },

    clearTable: function (tbody) { if (tbody) tbody.innerHTML = ''; },

    updateRecentAlertsTable: function (alerts) {
        if (!recentAlertsTableBody) return;
        this.clearTable(recentAlertsTableBody);
        if (!alerts || alerts.length === 0) {
            const row = recentAlertsTableBody.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 6;
            cell.textContent = 'No suspicious activities detected.';
            cell.style.textAlign = 'center'; cell.style.color = 'var(--text-muted)';
            return;
        }
        const alertsToShow = alerts.slice(0, 10); // Show max 10
        alertsToShow.forEach(alert => {
            const row = recentAlertsTableBody.insertRow();
            const severity = this.getSeverityDetailsFromAlert(alert);
            row.insertCell().innerHTML = `<span class="severity-badge ${severity.class}">${severity.text}</span>`;
            row.insertCell().textContent = alert.Prediction || 'N/A';
            row.insertCell().textContent = alert['Src IP'] || alert['Source IP'] || 'N/A';
            row.insertCell().textContent = alert['Dst IP'] || alert['Destination IP'] || 'N/A';
            row.insertCell().textContent = alert.Timestamp ? new Date(alert.Timestamp).toLocaleString() : 'N/A';
            row.insertCell().innerHTML = `<a href="#" class="details-link" data-flowid="${alert['Flow ID'] || ''}">Details</a>`;
        });
    },

    getSeverityDetailsFromAlert: function (alert) {
        let severityText = 'Low', severityClass = 'severity-low';
        const prediction = alert.Prediction ? String(alert.Prediction).toLowerCase() : '';
        const probability = typeof alert.Prediction_Probability === 'number' ? alert.Prediction_Probability : 0;

        if (prediction.includes('critical') || (prediction !== 'benign' && probability > 0.9)) {
            severityText = 'Critical'; severityClass = 'severity-critical';
        } else if (prediction.includes('high') || (prediction !== 'benign' && probability > 0.75)) { // Adjusted threshold
            severityText = 'High'; severityClass = 'severity-high';
        } else if (prediction.includes('medium') || (prediction !== 'benign' && probability > 0.5)) {
            severityText = 'Medium'; severityClass = 'severity-medium';
        } else if (prediction === 'benign' || prediction === '') {
            severityText = 'Info'; severityClass = 'severity-info'; // Should be a specific class if you want color
        }
        return { text: severityText, class: severityClass, level: severityText };
    },

    updateDashboardSummary: function (data) {
        if (totalThreatsElement) totalThreatsElement.textContent = data.totalThreats ?? 'N/A';
        if (criticalAlertsElement) criticalAlertsElement.textContent = data.criticalAlerts ?? 'N/A';
        if (unresolvedThreatsElement) unresolvedThreatsElement.textContent = `${data.unresolvedThreats || data.totalThreats || 0} total threats detected`;

        const normalTrafficEl = document.getElementById('normalTraffic');
        const suspiciousTrafficEl = document.getElementById('suspiciousTraffic');
        const maliciousTrafficEl = document.getElementById('maliciousTraffic');
        if (data.trafficAnalysisDataForCurrentScan) {
            if (normalTrafficEl) normalTrafficEl.textContent = `${(data.trafficAnalysisDataForCurrentScan.normal || 0).toFixed(2)} MB`;
            if (suspiciousTrafficEl) suspiciousTrafficEl.textContent = `${(data.trafficAnalysisDataForCurrentScan.suspicious || 0).toFixed(2)} MB`;
            if (maliciousTrafficEl) maliciousTrafficEl.textContent = `${(data.trafficAnalysisDataForCurrentScan.malicious || 0).toFixed(2)} MB`;
        }
        const activeAttacksEl = document.getElementById('activeAttacks');
        const countriesEl = document.getElementById('countries');
        const totalTodayEl = document.getElementById('totalToday');
        if (data.globalThreatMap) {
            if (activeAttacksEl) activeAttacksEl.textContent = data.globalThreatMap.activeAttacks || 0;
            if (countriesEl) countriesEl.textContent = data.globalThreatMap.countries || 0;
            if (totalTodayEl) totalTodayEl.textContent = data.globalThreatMap.totalToday || 0;
        }
    },
    processCsvDataForThreatTrendsChart: function (csvRows) {
        if (!csvRows || csvRows.length === 0) return { labels: [], critical: [], high: [], medium: [], low: [] };
        const aggregatedData = {};
        csvRows.forEach(row => {
            if (!row.Timestamp) return;
            const severityDetails = this.getSeverityDetailsFromAlert(row);
            if (severityDetails.level === 'Info' || !severityDetails.level) return; // Skip Info level for trends
            let dateKey;
            try {
                const timestamp = new Date(row.Timestamp);
                if (isNaN(timestamp.getTime())) return;
                dateKey = timestamp.toISOString().split('T')[0]; // Group by day
            } catch (e) { return; }
            if (!aggregatedData[dateKey]) aggregatedData[dateKey] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            if (aggregatedData[dateKey][severityDetails.level] !== undefined) aggregatedData[dateKey][severityDetails.level]++;
        });
        const sortedDates = Object.keys(aggregatedData).sort((a, b) => new Date(a) - new Date(b));
        const result = { labels: [], critical: [], high: [], medium: [], low: [] };
        sortedDates.forEach(date => {
            result.labels.push(new Date(date).toLocaleDateString([], { month: 'short', day: 'numeric' })); // Format date
            result.critical.push(aggregatedData[date].Critical);
            result.high.push(aggregatedData[date].High);
            result.medium.push(aggregatedData[date].Medium);
            result.low.push(aggregatedData[date].Low);
        });
        return result;
    }
};

// --- IPC EVENT HANDLERS ---
const IPCManager = {
    initialSettingsData: null,

    setupListeners: function () {
        if (!window.electronAPI) {
            console.error("window.electronAPI is not defined.");
            return;
        }

        window.electronAPI.onStatusUpdate((message) => {
            console.log("Status:", message.trim());
            if (statusArea) { statusArea.textContent += message + '\n'; statusArea.scrollTop = statusArea.scrollHeight; }

            if (message.includes("Starting Network Analysis Pipeline")) {
                UIUpdater.updateDetectionStatus(null, 'Detection Starting...');
                if (startAnalysisButton) startAnalysisButton.disabled = true;
                if (stopAnalysisButton) stopAnalysisButton.disabled = false;
            } else if (message.includes("Prediction Module Finished Successfully") || message.includes("Pipeline Completed Successfully")) {
                UIUpdater.updateDetectionStatus(false, 'Analysis Complete');
                // Button state managed by onResultsData or onAnalysisProcessTerminated
            } else if (message.toLowerCase().includes("error") || message.toLowerCase().includes("failed") || message.includes("LỖI")) {
                // Don't prematurely set to Inactive here, wait for full termination or successful result processing.
                // Python process might log an error but still complete or main.js handles the failure state.
                console.error("Error message received:", message.trim());
            } else if (message.includes("Starting Prediction Module")) {
                UIUpdater.updateDetectionStatus(null, 'Analyzing...');
            }
        });

        window.electronAPI.onClearResults(() => {
            if (recentAlertsTableBody) UIUpdater.clearTable(recentAlertsTableBody);
            if (totalThreatsElement) totalThreatsElement.textContent = '0';
            if (criticalAlertsElement) criticalAlertsElement.textContent = '0';
            if (unresolvedThreatsElement) unresolvedThreatsElement.textContent = '0 total threats detected';
            ChartManager.clearAllChartData();
        });

        window.electronAPI.onResultsData((data) => {
            console.log("Results Data Received (partial):", { keys: Object.keys(data) });
            UIUpdater.updateDashboardSummary(data);
            if (data.suspicious) UIUpdater.updateRecentAlertsTable(data.suspicious);

            if (data.suspicious && Array.isArray(data.suspicious)) {
                const trendData = UIUpdater.processCsvDataForThreatTrendsChart(data.suspicious);
                ChartManager.updateThreatTrends(trendData);
            }
            if (data.scanHistory) ChartManager.updateTrafficAnalysis(data.scanHistory);
            if (data.aptTypeCounts) ChartManager.updateAptTypeDistribution(data.aptTypeCounts);
            if (data.topSourceAPTIPs) ChartManager.updateTopIpChart('topAptSourceIp', data.topSourceAPTIPs);
            if (data.topDestAPTIPs) ChartManager.updateTopIpChart('topAptDestIp', data.topDestAPTIPs);
            if (data.aptProtocolCounts) ChartManager.updateAptProtocol(data.aptProtocolCounts);

            if (startAnalysisButton) { startAnalysisButton.disabled = false; startAnalysisButton.textContent = "Start Analysis"; }
            if (stopAnalysisButton) stopAnalysisButton.disabled = true;
            UIUpdater.updateDetectionStatus(false, 'Results Loaded'); // More accurate status
        });

        window.electronAPI.onSystemMetrics((metrics) => {
            if (systemStatusTextElement) systemStatusTextElement.textContent = "Active";
            if (cpuUsageElement) cpuUsageElement.textContent = metrics.cpu?.toFixed(1) + '%' || '--%';
            if (memoryUsageElement) memoryUsageElement.textContent = metrics.mem?.toFixed(1) + '%' || '--%';
            if (networkUsageElement) networkUsageElement.textContent = (metrics.net / 1024)?.toFixed(1) + ' KB/s' || '-- KB/s';
            ChartManager.updateSystemMetrics(metrics.timestamp, metrics.cpu, metrics.mem, (metrics.net / 1024));
        });

        window.electronAPI.onSettingsUpdated((settings) => {
            console.log("Settings updated from main:", settings);
            this.initialSettingsData = { ...this.initialSettingsData, ...settings }; // Merge updates
            if (settings?.theme) {
                ThemeManager.applyTheme(settings.theme);
                if (Navigation.activePage === 'setting') ThemeManager.updateThemeSelectElement();
            }
            if (settings?.scanHistory && Navigation.activePage === 'dashboard' && ChartManager.areChartsInitialized()) {
                ChartManager.updateTrafficAnalysis(settings.scanHistory);
            }
            // Repopulate settings page if it's active and other settings changed
            if (Navigation.activePage === 'setting') PageInitializers.setting();
        });

        window.electronAPI.onInitialSettings((settings) => {
            console.log("Initial settings from main:", settings);
            this.initialSettingsData = settings;
            if (settings) {
                ThemeManager.applyTheme(settings.theme || 'dark');
                if (settings.scanHistory && Navigation.activePage === 'dashboard' && ChartManager.areChartsInitialized()) {
                    ChartManager.updateTrafficAnalysis(settings.scanHistory);
                }
            }
        });

        window.electronAPI.onAnalysisProcessTerminated(() => {
            console.log("Analysis terminated by main process.");
            UIUpdater.updateDetectionStatus(false, 'Analysis Stopped');
            if (startAnalysisButton) { startAnalysisButton.disabled = false; startAnalysisButton.textContent = "Start Analysis"; }
            if (stopAnalysisButton) stopAnalysisButton.disabled = true;
            if (statusArea) statusArea.textContent += 'Analysis stopped by user or due to an error.\n';
        });
    }
};

// --- MAIN INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    Navigation.init();
    IPCManager.setupListeners();

    const minimizeBtn = document.getElementById('minimize-btn');
    const maximizeRestoreBtn = document.getElementById('maximize-restore-btn');
    const closeBtn = document.getElementById('close-btn');
    const maximizeIcon = document.getElementById('maximize-icon');
    const restoreIcon = document.getElementById('restore-icon');

    if (window.electronAPI) {
        if (minimizeBtn) minimizeBtn.addEventListener('click', () => window.electronAPI.minimizeApp());
        if (maximizeRestoreBtn) maximizeRestoreBtn.addEventListener('click', () => window.electronAPI.maximizeRestoreApp());
        if (closeBtn) closeBtn.addEventListener('click', () => window.electronAPI.closeApp());

        window.electronAPI.onWindowMaximized(() => {
            if (maximizeIcon) maximizeIcon.style.display = 'none';
            if (restoreIcon) restoreIcon.style.display = 'block';
            if (maximizeRestoreBtn) maximizeRestoreBtn.title = 'Restore';
        });
        window.electronAPI.onWindowUnmaximized(() => {
            if (maximizeIcon) maximizeIcon.style.display = 'block';
            if (restoreIcon) restoreIcon.style.display = 'none';
            if (maximizeRestoreBtn) maximizeRestoreBtn.title = 'Maximize';
        });
    }
    Navigation.loadPage('dashboard'); // Load initial page
});