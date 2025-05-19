const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    startAnalysis: () => ipcRenderer.send('start-analysis'),
    // stopAnalysis: () => ipcRenderer.send('stop-analysis'), // Nếu có nút stop
    onStatusUpdate: (callback) => ipcRenderer.on('status-update', (_event, value) => callback(value)),
    onResultsData: (callback) => ipcRenderer.on('results-data', (_event, value) => callback(value)),
    onClearResults: (callback) => ipcRenderer.on('clear-results', () => callback()),
    onSystemMetrics: (callback) => ipcRenderer.on('system-metrics', (_event, value) => callback(value)),

    // Thêm các hàm cho điều khiển cửa sổ
    minimizeApp: () => ipcRenderer.send('minimize-app'),
    maximizeRestoreApp: () => ipcRenderer.send('maximize-restore-app'),
    closeApp: () => ipcRenderer.send('close-app'),
    onWindowMaximized: (callback) => ipcRenderer.on('window-maximized', callback),
    onWindowUnmaximized: (callback) => ipcRenderer.on('window-unmaximized', callback)
});