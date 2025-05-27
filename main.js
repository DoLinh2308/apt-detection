// main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const csv = require('csv-parser');
const si = require('systeminformation');
// const Store = require('electron-store');

// --- PATHS AND CONSTANTS ---
const BASE_DIR = __dirname;
const BACKEND_DIR = path.join(BASE_DIR, 'backend');
const PYTHON_SCRIPT_PATH = path.join(BACKEND_DIR, 'main.py');
const RESULTS_DIR = path.join(BACKEND_DIR, 'results');
const VENV_DIR = path.join(BASE_DIR, '.venv'); // Ensure this matches your venv path
const PYTHON_EXECUTABLE = process.platform === 'win32'
    ? path.join(VENV_DIR, 'Scripts', 'python.exe')
    : path.join(VENV_DIR, 'bin', 'python');

const PREDICTIONS_FILE = path.join(RESULTS_DIR, 'network_flows_Predictions.csv');
const SUSPICIOUS_FILE = path.join(RESULTS_DIR, 'Suspicious_network_flows_Predictions.csv');
const TRAFFIC_ANALYSIS_FILE = path.join(RESULTS_DIR, 'traffic_analysis.csv');
const GLOBAL_THREAT_MAP_FILE = path.join(RESULTS_DIR, 'global_threat_map.csv');

const MAX_SCAN_HISTORY_LENGTH = 20;

// --- GLOBAL VARIABLES ---
let mainWindow;
let pythonProcess = null;
let analysisManuallyStopped = false;
let systemMetricsInterval = null;
let store;

// --- STORE INITIALIZATION ---
async function initializeStore() {
    try {
        const { default: Store } = await import('electron-store'); // Sử dụng dynamic import
        store = new Store({
            defaults: {
                theme: 'dark',
                scanHistory: [],
                enableEmailNotifications: false,
                emailSenderAddress: '',
                emailSenderPassword: '',
                emailReceiverAddress: '',
                emailSmtpServer: 'smtp.gmail.com',
                emailSmtpPort: 587,
                enableTelegramNotifications: false,
                telegramBotToken: '',
                telegramChatId: ''
            }
        });
        console.log("Electron-store initialized successfully. Config file path:", store.path);
        console.log("Initial store content (sample):", {
            theme: store.get('theme'),
            emailEnabled: store.get('enableEmailNotifications')
        });
    } catch (error) {
        console.error("CRITICAL: Failed to initialize electron-store. See details below.");
        console.error("Error Object:", error);
        console.error("Error Name:", error.name);
        console.error("Error Message:", error.message);
        console.error("Error Stack:", error.stack);
        store = null;
    }
}

// --- SETTINGS MODULE ---
const SettingsHandler = {
    save: (settingsToSave) => {
        if (!store) {
            console.error("Store not initialized or initialization failed. Cannot save settings.");
            if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
                mainWindow.webContents.send('status-update', 'Lỗi: Store chưa sẵn sàng, không thể lưu cài đặt.');
            }
            return;
        }
        console.log("Attempting to save settings:", Object.keys(settingsToSave));

        const currentSettings = SettingsHandler.load(); // Get all current settings
        const updatedSettings = { ...currentSettings, ...settingsToSave }; // Merge

        // Explicitly set each known key
        if (typeof settingsToSave.theme !== 'undefined') store.set('theme', settingsToSave.theme);

        // Email settings
        if (typeof settingsToSave.enableEmailNotifications !== 'undefined') store.set('enableEmailNotifications', settingsToSave.enableEmailNotifications);
        if (typeof settingsToSave.emailSenderAddress !== 'undefined') store.set('emailSenderAddress', settingsToSave.emailSenderAddress);
        // SECURITY: Only update password if a new one is explicitly provided.
        //Renderer clears the field, so an empty string here means "don't change unless a value is entered".
        if (settingsToSave.emailSenderPassword && settingsToSave.emailSenderPassword.length > 0) {
            store.set('emailSenderPassword', settingsToSave.emailSenderPassword);
            console.warn("SECURITY WARNING: Email sender password has been updated in electron-store.");
        } else if (settingsToSave.hasOwnProperty('emailSenderPassword') && settingsToSave.emailSenderPassword === '') {
            // If renderer sent an empty string, it means user cleared it OR didn't want to update.
            // We do NOT clear the stored password if the field was simply empty on save.
            // Only a deliberate action to *remove* the password (if we had such UI) or change it would update.
            console.log("Email sender password field was empty, stored password unchanged (if any).");
        }

        if (typeof settingsToSave.emailReceiverAddress !== 'undefined') store.set('emailReceiverAddress', settingsToSave.emailReceiverAddress);
        if (typeof settingsToSave.emailSmtpServer !== 'undefined') store.set('emailSmtpServer', settingsToSave.emailSmtpServer);
        if (typeof settingsToSave.emailSmtpPort !== 'undefined') store.set('emailSmtpPort', settingsToSave.emailSmtpPort);

        // Telegram settings
        if (typeof settingsToSave.enableTelegramNotifications !== 'undefined') store.set('enableTelegramNotifications', settingsToSave.enableTelegramNotifications);
        if (settingsToSave.telegramBotToken && settingsToSave.telegramBotToken.length > 0) { // Only update if new value
            store.set('telegramBotToken', settingsToSave.telegramBotToken);
            console.warn("SECURITY WARNING: Telegram Bot Token has been updated in electron-store.");
        }
        if (settingsToSave.telegramChatId && settingsToSave.telegramChatId.length > 0) { // Only update if new value
            store.set('telegramChatId', settingsToSave.telegramChatId);
        }


        console.log('Settings saved. Theme:', store.get('theme'), "Email Enabled:", store.get('enableEmailNotifications'));

        // Notify renderer about all *potentially* updated settings for consistency
        // Exclude passwords from being sent back to renderer for display.
        const settingsForRenderer = { ...SettingsHandler.load() };
        delete settingsForRenderer.emailSenderPassword; // Don't send password back

        BrowserWindow.getAllWindows().forEach(win => {
            if (win && win.webContents && !win.isDestroyed()) {
                win.webContents.send('settings-updated', settingsForRenderer);
            }
        });
    },
    load: () => {
        if (!store) {
            console.error("Store not initialized or initialization failed. Returning default settings skeleton.");
            return {
                theme: 'dark', scanHistory: [], enableEmailNotifications: false,
                emailSenderAddress: '', emailSenderPassword: '', emailReceiverAddress: '',
                emailSmtpServer: '', emailSmtpPort: '', enableTelegramNotifications: false,
                telegramBotToken: '', telegramChatId: ''
            };
        }
        // For security, never return emailSenderPassword directly via general load if it's for UI display.
        // The UI should manage password fields separately (e.g., only accept new input).
        // However, for internal use (like passing to Python - if we did that), loading it is fine.
        // The `onInitialSettings` and `onSettingsUpdated` will have password removed before sending to renderer.
        return {
            theme: store.get('theme', 'dark'),
            scanHistory: store.get('scanHistory', []),
            enableEmailNotifications: store.get('enableEmailNotifications', false),
            emailSenderAddress: store.get('emailSenderAddress', ''),
            // Do NOT send emailSenderPassword back to renderer for general display
            // It will be available if Python side needs to read it, but UI shouldn't autofill it.
            emailSenderPassword: store.get('emailSenderPassword', ''), // internal load for now
            emailReceiverAddress: store.get('emailReceiverAddress', ''),
            emailSmtpServer: store.get('emailSmtpServer', 'smtp.gmail.com'),
            emailSmtpPort: store.get('emailSmtpPort', 587),
            enableTelegramNotifications: store.get('enableTelegramNotifications', false),
            telegramBotToken: store.get('telegramBotToken', ''),
            telegramChatId: store.get('telegramChatId', '')
        };
    },
    updateScanHistory: (currentSummary, isSuccess, suspiciousFlowsCount) => {
        if (!store) {
            console.error("Store not initialized. Cannot update scan history.");
            return [];
        }
        let scanHistory = store.get('scanHistory', []);
        if (isSuccess) {
            scanHistory.push({
                timestamp: Date.now(),
                normal: currentSummary.normal || 0,
                suspicious: currentSummary.suspicious || 0,
                malicious: currentSummary.malicious || 0,
                threatsDetected: suspiciousFlowsCount
            });
            if (scanHistory.length > MAX_SCAN_HISTORY_LENGTH) {
                scanHistory = scanHistory.slice(-MAX_SCAN_HISTORY_LENGTH);
            }
            store.set('scanHistory', scanHistory);
        }
        return scanHistory;
    }
};

// --- WINDOW MANAGEMENT ---
const AppWindow = {
    create: () => {
        mainWindow = new BrowserWindow({
            width: 1300, // Wider for more complex settings
            height: 850, // Taller
            frame: false,
            titleBarStyle: 'hidden',
            webPreferences: {
                preload: path.join(BASE_DIR, 'frontend/preload.js'),
                contextIsolation: true,
                nodeIntegration: false,
                devTools: !app.isPackaged
            }
        });
        mainWindow.setMenuBarVisibility(false);

        if (!fs.existsSync(PYTHON_EXECUTABLE)) {
            console.error(`ERROR: Python executable not found at: ${PYTHON_EXECUTABLE}`);
            mainWindow.webContents.once('did-finish-load', () => {
                if (mainWindow && !mainWindow.isDestroyed()) {
                    mainWindow.webContents.send('status-update', `LỖI: Không tìm thấy Python tại ${PYTHON_EXECUTABLE}.`);
                }
            });
        }

        mainWindow.loadFile(path.join(BASE_DIR, 'frontend/index.html'));

        mainWindow.webContents.on('did-finish-load', () => {
            SystemMonitor.start(5000);
            if (mainWindow && !mainWindow.isDestroyed()) {
                let initialSettings = SettingsHandler.load();
                delete initialSettings.emailSenderPassword; // Never send password to renderer for auto-fill
                delete initialSettings.telegramBotToken; // Don't auto-fill sensitive tokens
                console.log("Sending initial settings (censored) to renderer:", Object.keys(initialSettings));
                mainWindow.webContents.send('initial-settings', initialSettings);
            }
        });

        mainWindow.on('closed', () => {
            SystemMonitor.stop();
            if (pythonProcess) {
                analysisManuallyStopped = true;
                pythonProcess.kill('SIGTERM'); // Or SIGKILL if necessary
                pythonProcess = null;
            }
            mainWindow = null;
        });

        mainWindow.on('maximize', () => mainWindow.webContents.send('window-maximized'));
        mainWindow.on('unmaximize', () => mainWindow.webContents.send('window-unmaximized'));

        if (!app.isPackaged) mainWindow.webContents.openDevTools();
    },

    setupIPCControls: () => {
        ipcMain.on('minimize-app', () => mainWindow?.minimize());
        ipcMain.on('maximize-restore-app', () => {
            if (mainWindow) mainWindow.isMaximized() ? mainWindow.restore() : mainWindow.maximize();
        });
        ipcMain.on('close-app', () => mainWindow?.close());
    }
};

// --- SYSTEM MONITOR MODULE ---
const SystemMonitor = {
    start: async (intervalMs) => {
        if (systemMetricsInterval) SystemMonitor.stop();
        const sendMetrics = async () => {
            try {
                const cpu = await si.currentLoad();
                const mem = await si.mem();
                const netStats = await si.networkStats(); // Get default interface
                const memPercent = (mem.active / mem.total) * 100;
                // Sum rx_sec and tx_sec for a rough total speed. Could pick a specific interface if needed.
                const currentNetSpeed = netStats.reduce((acc, curr) => acc + (curr.rx_sec || 0) + (curr.tx_sec || 0), 0);


                if (mainWindow && !mainWindow.isDestroyed()) {
                    mainWindow.webContents.send('system-metrics', {
                        timestamp: Date.now(),
                        cpu: cpu.currentLoad,
                        mem: memPercent,
                        net: currentNetSpeed // Bytes per second
                    });
                }
            } catch (e) {
                console.error('Error getting system metrics:', e.message);
            }
        };
        await sendMetrics(); // Initial call
        systemMetricsInterval = setInterval(sendMetrics, intervalMs);
    },
    stop: () => {
        if (systemMetricsInterval) {
            clearInterval(systemMetricsInterval);
            systemMetricsInterval = null;
        }
    }
};

// --- RESULTS PROCESSOR MODULE ---
const ResultsProcessor = {
    _readFilePromise: (filePath, dataArray, onDataCallback) => {
        return new Promise((resolve, reject) => {
            if (!fs.existsSync(filePath)) {
                resolve(); return; // File not found is not an error for this function's purpose
            }
            const stream = fs.createReadStream(filePath);
            stream.pipe(csv())
                .on('data', (row) => {
                    if (dataArray) dataArray.push(row);
                    if (onDataCallback) onDataCallback(row);
                })
                .on('end', () => resolve())
                .on('error', (error) => {
                    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', `Lỗi đọc ${path.basename(filePath)}.`);
                    reject(error);
                });
        });
    },

    _aggregateAPTStatistics: (suspiciousFlows) => {
        let aptTypeCounts = {}, topSourceAPTIPs = {}, topDestAPTIPs = {}, aptProtocolCounts = {};
        suspiciousFlows.forEach(flow => {
            const predictionType = flow.Prediction || "Unknown";
            aptTypeCounts[predictionType] = (aptTypeCounts[predictionType] || 0) + 1;
            const srcIp = flow['Src IP'] || "Unknown";
            topSourceAPTIPs[srcIp] = (topSourceAPTIPs[srcIp] || 0) + 1;
            const dstIp = flow['Dst IP'] || "Unknown";
            topDestAPTIPs[dstIp] = (topDestAPTIPs[dstIp] || 0) + 1;
            let protocolName = String(flow.Protocol || "Unknown");
            if (flow.Protocol === '6') protocolName = 'TCP';
            else if (flow.Protocol === '17') protocolName = 'UDP';
            else if (flow.Protocol === '1') protocolName = 'ICMP'; // Added ICMP
            aptProtocolCounts[protocolName] = (aptProtocolCounts[protocolName] || 0) + 1;
        });
        const getTopN = (obj, n) => Object.entries(obj).sort(([, a], [, b]) => b - a).slice(0, n).reduce((r, [k, v]) => ({ ...r, [k]: v }), {});
        return {
            aptTypeCounts,
            topSourceAPTIPs: getTopN(topSourceAPTIPs, 5),
            topDestAPTIPs: getTopN(topDestAPTIPs, 5),
            aptProtocolCounts
        };
    },

    _getCurrentScanTrafficSummary: (trafficDataFromFile) => {
        let summary = { normal: 0, suspicious: 0, malicious: 0 };
        if (trafficDataFromFile.length > 0 && trafficDataFromFile[0]) {
            summary.normal = parseFloat(trafficDataFromFile[0].normal) || 0;
            summary.suspicious = parseFloat(trafficDataFromFile[0].suspicious) || 0;
            summary.malicious = parseFloat(trafficDataFromFile[0].malicious) || 0;
        }
        return summary;
    },

    processAndSend: async (isSuccess) => {
        if (!mainWindow || mainWindow.isDestroyed()) return;

        const allPredictions = [], suspiciousFlows = [], trafficData = [], globalThreatMapData = [];
        let totalThreats = 0, criticalAlerts = 0;

        const readPromises = [
            ResultsProcessor._readFilePromise(PREDICTIONS_FILE, allPredictions),
            ResultsProcessor._readFilePromise(SUSPICIOUS_FILE, suspiciousFlows, (data) => {
                totalThreats++;
                const prediction = data.Prediction ? String(data.Prediction).toLowerCase() : '';
                const probability = parseFloat(data.Prediction_Probability);
                if (prediction.includes('critical') || (probability && probability > 0.9)) criticalAlerts++;
            }),
            ResultsProcessor._readFilePromise(TRAFFIC_ANALYSIS_FILE, trafficData),
            ResultsProcessor._readFilePromise(GLOBAL_THREAT_MAP_FILE, globalThreatMapData)
        ];

        try {
            await Promise.all(readPromises);
            const currentScanTraffic = ResultsProcessor._getCurrentScanTrafficSummary(trafficData);
            const aptStats = ResultsProcessor._aggregateAPTStatistics(suspiciousFlows);
            const updatedScanHistory = SettingsHandler.updateScanHistory(currentScanTraffic, isSuccess, suspiciousFlows.length);

            mainWindow.webContents.send('results-data', {
                suspicious: suspiciousFlows,
                totalThreats: totalThreats, criticalAlerts: criticalAlerts,
                trafficAnalysisDataForCurrentScan: currentScanTraffic,
                globalThreatMap: globalThreatMapData[0] || { activeAttacks: 0, countries: 0, totalToday: 0 },
                aptTypeCounts: aptStats.aptTypeCounts,
                topSourceAPTIPs: aptStats.topSourceAPTIPs,
                topDestAPTIPs: aptStats.topDestAPTIPs,
                aptProtocolCounts: aptStats.aptProtocolCounts,
                scanHistory: updatedScanHistory
            });
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', 'Đã tải và xử lý kết quả.');
        } catch (error) {
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', `Lỗi xử lý file kết quả.`);
            console.error("Error in processAndSend:", error);
        }
    }
};

// --- ANALYSIS RUNNER MODULE ---
const AnalysisRunner = {
    start: () => {
        if (pythonProcess) {
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', 'Phân tích đang chạy.');
            return;
        }
        if (!fs.existsSync(PYTHON_EXECUTABLE)) {
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', `LỖI: Python không tìm thấy tại ${PYTHON_EXECUTABLE}.`);
            return;
        }

        analysisManuallyStopped = false;
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('status-update', 'Bắt đầu phân tích...');
            mainWindow.webContents.send('clear-results');
        }

        if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });
        [PREDICTIONS_FILE, SUSPICIOUS_FILE, TRAFFIC_ANALYSIS_FILE, GLOBAL_THREAT_MAP_FILE].forEach(file => {
            if (fs.existsSync(file)) fs.unlinkSync(file);
        });

        // Pass configured settings to Python if needed (currently Python uses .env)
        // For example: const currentSettings = SettingsHandler.load();
        // const spawnArgs = [PYTHON_SCRIPT_PATH, '--email-pass', currentSettings.emailSenderPassword];
        // For simplicity, Python will still use .env files.
        pythonProcess = spawn(PYTHON_EXECUTABLE, [PYTHON_SCRIPT_PATH], { cwd: BACKEND_DIR });

        pythonProcess.stdout.on('data', (data) => {
            const message = data.toString();
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', message);
        });
        pythonProcess.stderr.on('data', (data) => {
            const message = data.toString();
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', `PYTHON_ERR: ${message}`);
        });
        pythonProcess.on('close', (code, signal) => {
            const wasKilledByUser = analysisManuallyStopped || signal === 'SIGTERM' || signal === 'SIGINT';
            let statusMsg = '', processSuccess = false;

            if (wasKilledByUser) statusMsg = 'Phân tích dừng bởi người dùng.';
            else if (code !== 0) statusMsg = `Phân tích thất bại (mã ${code}).`;
            else { statusMsg = `Phân tích hoàn tất.`; processSuccess = true; }

            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('status-update', statusMsg);
                if (wasKilledByUser || code !== 0) mainWindow.webContents.send('analysis-process-terminated');
            }
            ResultsProcessor.processAndSend(processSuccess);
            pythonProcess = null;
            analysisManuallyStopped = false;
        });
        pythonProcess.on('error', (err) => {
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('status-update', `LỖI KHỞI CHẠY PYTHON: ${err.message}`);
                mainWindow.webContents.send('analysis-process-terminated');
            }
            pythonProcess = null;
        });
    },
    stop: () => {
        if (pythonProcess) {
            analysisManuallyStopped = true;
            pythonProcess.kill('SIGTERM');
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('status-update', 'Đang dừng phân tích...');
        } else {
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('status-update', 'Không có phân tích nào để dừng.');
                mainWindow.webContents.send('analysis-process-terminated');
            }
        }
    },
    setupIPC: () => {
        ipcMain.on('start-analysis', AnalysisRunner.start);
        ipcMain.on('stop-analysis', AnalysisRunner.stop);
    }
};

// --- APP LIFECYCLE ---
app.whenReady().then(async () => {
    await initializeStore();
    AppWindow.create();
    AppWindow.setupIPCControls();
    AnalysisRunner.setupIPC();
    ipcMain.on('save-settings', (event, settings) => {
        if (!store) {
             console.error("Attempted to save settings, but store is not initialized.");
             event.reply('status-update', 'Lỗi nghiêm trọng: Store không khả dụng.'); // Gửi phản hồi nếu cần
             return;
        }
        SettingsHandler.save(settings);
    });

    ipcMain.handle('load-settings', async () => { // Có thể để async nếu có gì đó bất đồng bộ
        if (!store) {
             console.error("Attempted to load settings, but store is not initialized.");
             // Trả về cấu trúc mặc định để UI không bị lỗi
             return {
                theme: 'dark', scanHistory: [], enableEmailNotifications: false,
                emailSenderAddress: '', emailSenderPassword: '', emailReceiverAddress: '',
                emailSmtpServer: '', emailSmtpPort: '', enableTelegramNotifications: false,
                telegramBotToken: '', telegramChatId: ''
            };
        }
        let settings = SettingsHandler.load();
        delete settings.emailSenderPassword;
        delete settings.telegramBotToken;
        return settings;
    });

    app.on('activate', async () => { // Chuyển thành async
        if (BrowserWindow.getAllWindows().length === 0) {
            if (!store) { // Nếu store chưa được init do app activate trước whenReady (hiếm)
                await initializeStore();
            }
            AppWindow.create();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});