// frontend/preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Analysis
    startAnalysis: () => ipcRenderer.send('start-analysis'),
    stopAnalysis: () => ipcRenderer.send('stop-analysis'),
    onStatusUpdate: (callback) => ipcRenderer.on('status-update', (_event, value) => callback(value)),
    onResultsData: (callback) => ipcRenderer.on('results-data', (_event, value) => callback(value)),
    onClearResults: (callback) => ipcRenderer.on('clear-results', () => callback()),
    onAnalysisProcessTerminated: (callback) => ipcRenderer.on('analysis-process-terminated', () => callback()),

    // System Metrics
    onSystemMetrics: (callback) => ipcRenderer.on('system-metrics', (_event, value) => callback(value)),

    // Settings
    saveSettings: (settings) => ipcRenderer.send('save-settings', settings),
    loadSettings: () => ipcRenderer.invoke('load-settings'),
    onSettingsUpdated: (callback) => ipcRenderer.on('settings-updated', (_event, value) => callback(value)),
    onInitialSettings: (callback) => ipcRenderer.on('initial-settings', (_event, value) => callback(value)),


    // Window Controls
    minimizeApp: () => ipcRenderer.send('minimize-app'),
    maximizeRestoreApp: () => ipcRenderer.send('maximize-restore-app'),
    closeApp: () => ipcRenderer.send('close-app'),
    onWindowMaximized: (callback) => ipcRenderer.on('window-maximized', callback),
    onWindowUnmaximized: (callback) => ipcRenderer.on('window-unmaximized', callback)
});