const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const csv = require('csv-parser');
const si = require('systeminformation'); // Import systeminformation



// Đường dẫn đến thư mục backend
const backendDir = path.join(__dirname, 'backend');
// Đường dẫn đến script Python chính
const pythonScriptPath = path.join(backendDir, 'main.py');
// Đường dẫn đến thư mục results
const resultsDir = path.join(backendDir, 'results');

// Đường dẫn đến thư mục venv
const envDir = path.join(__dirname, '.venv');

const venvDir = path.join(envDir); 
const pythonExecutable = process.platform === 'win32'
    ? path.join(venvDir, 'Scripts', 'python.exe') // Cho Windows
    : path.join(venvDir, 'bin', 'python');        // Cho macOS/Linux

// Kiểm tra xem file python có tồn tại không (tùy chọn nhưng hữu ích)
if (!fs.existsSync(pythonExecutable)) {
    console.error(`LỖI: Không tìm thấy Python executable tại: ${pythonExecutable}`);
    // Có thể hiển thị lỗi này cho người dùng hoặc thoát ứng dụng sớm
    mainWindow.webContents.send('status-update', `LỖI: Không tìm thấy Python tại ${pythonExecutable}. Hãy đảm bảo venv đã được tạo và đường dẫn chính xác.`);
}
const predictionsFile = path.join(resultsDir, 'network_flows_Predictions.csv'); 
const suspiciousFile = path.join(resultsDir, 'Suspicious_network_flows_Predictions.csv'); 


let systemMetricsInterval = null;
async function startSystemMetricsMonitoring(intervalMs = 5000) { // Lấy mỗi 5 giây
    stopSystemMetricsMonitoring(); // Dừng interval cũ nếu có

    const sendMetrics = async () => {
        try {
            const cpu = await si.currentLoad(); // % CPU tổng
            const mem = await si.mem(); // Thông tin memory
            const netStats = await si.networkStats(); // Lấy network stats (bytes/sec)

            const memPercent = mem.active / mem.total * 100;
            // Lấy tổng bytes nhận/gửi mỗi giây (cần chọn interface phù hợp hoặc tính tổng)
            // Ví dụ đơn giản: lấy interface đầu tiên
            const currentNetSpeed = netStats.length > 0 ? (netStats[0].rx_sec + netStats[0].tx_sec) : 0;

            if (mainWindow && mainWindow.webContents) {
                mainWindow.webContents.send('system-metrics', {
                    timestamp: Date.now(),
                    cpu: cpu.currentLoad,
                    mem: memPercent,
                    net: currentNetSpeed // Bytes/second
                });
            }
        } catch (e) {
            console.error('Error getting system metrics:', e);
            // Có thể dừng theo dõi nếu lỗi liên tục
            // stopSystemMetricsMonitoring();
        }
    };

    await sendMetrics(); // Gửi ngay lần đầu
    systemMetricsInterval = setInterval(sendMetrics, intervalMs);
}

function stopSystemMetricsMonitoring() {
    if (systemMetricsInterval) {
        clearInterval(systemMetricsInterval);
        systemMetricsInterval = null;
        console.log("Stopped system metrics monitoring.");
    }
}


let mainWindow;
let pythonProcess = null;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 700,
        frame: false,
        titleBarStyle: 'hidden',
        webPreferences: {
            preload: path.join(__dirname, 'frontend/preload.js'),
            contextIsolation: true, // Nên bật để bảo mật
            nodeIntegration: false // Nên tắt để bảo mật
        }
    });
    mainWindow.setMenuBarVisibility(false); // Chỉ ẩn, có thể hiện lại bằng Alt (Windows/Linux)


    // Lắng nghe các sự kiện từ Renderer Process để điều khiển cửa sổ
    ipcMain.on('minimize-app', () => {
        if (mainWindow) mainWindow.minimize(); // Sửa từ win sang mainWindow
    });

    ipcMain.on('maximize-restore-app', () => {
        if (mainWindow) { // Sửa từ win sang mainWindow
            if (mainWindow.isMaximized()) {
                mainWindow.restore();
            } else {
                mainWindow.maximize();
            }
        }
    });

    ipcMain.on('close-app', () => {
        if (mainWindow) mainWindow.close(); // Sửa từ win sang mainWindow
    });

    // (Tùy chọn) Gửi trạng thái maximize cho renderer để cập nhật UI nút
    if (mainWindow) { // Thêm kiểm tra mainWindow tồn tại
        mainWindow.on('maximize', () => {
            if (mainWindow && mainWindow.webContents) mainWindow.webContents.send('window-maximized');
        });

        mainWindow.on('unmaximize', () => {
            if (mainWindow && mainWindow.webContents) mainWindow.webContents.send('window-unmaximized');
        });
    }
    mainWindow.loadFile('frontend/index.html');
    mainWindow.webContents.on('did-finish-load', () => {
        startSystemMetricsMonitoring();
    });

    // Dừng theo dõi khi cửa sổ đóng
    mainWindow.on('closed', () => {
        stopSystemMetricsMonitoring();
        mainWindow = null;
    });

    mainWindow.webContents.openDevTools(); // Mở Developer Tools để debug
}

app.whenReady().then(() => {
    createWindow();
    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// Lắng nghe yêu cầu bắt đầu phân tích từ Renderer
ipcMain.on('start-analysis', (event) => {
    if (pythonProcess) {
        console.log('Analysis is already running.');
        mainWindow.webContents.send('status-update', 'Phân tích đang chạy.');
        return;
    }

    console.log(`Starting Python script: ${pythonExecutable} ${pythonScriptPath}`);
    mainWindow.webContents.send('status-update', 'Bắt đầu quá trình phân tích...');
    mainWindow.webContents.send('clear-results'); // Xóa kết quả cũ trên UI

    // Đảm bảo thư mục results tồn tại trước khi chạy
    if (!fs.existsSync(resultsDir)) {
        fs.mkdirSync(resultsDir, { recursive: true });
    }
    // Xóa file kết quả cũ nếu có
    if (fs.existsSync(predictionsFile)) fs.unlinkSync(predictionsFile);
    if (fs.existsSync(suspiciousFile)) fs.unlinkSync(suspiciousFile);


    pythonProcess = spawn(pythonExecutable, [pythonScriptPath], { cwd: path.join(__dirname, 'backend') }); // Đặt cwd nếu script Python cần chạy từ thư mục của nó

    pythonProcess.stdout.on('data', (data) => {
        const message = data.toString();
        console.log(`Python stdout: ${message}`);
        mainWindow.webContents.send('status-update', message); // Gửi log/status về UI
    });

    pythonProcess.stderr.on('data', (data) => {
        const message = data.toString();
        console.error(`Python stderr: ${message}`);
        mainWindow.webContents.send('status-update', `${message}`); // Gửi lỗi về UI
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python process exited with code ${code}`);
        mainWindow.webContents.send('status-update', `Phân tích hoàn tất (mã thoát: ${code}). Đang tải kết quả...`);
        pythonProcess = null;

        // Đọc và gửi kết quả sau khi tiến trình Python kết thúc
        readAndSendResults();
    });

    pythonProcess.on('error', (err) => {
        console.error('Failed to start Python process:', err);
        mainWindow.webContents.send('status-update', `LỖI NGHIÊM TRỌNG: Không thể khởi chạy tiến trình Python. ${err.message}`);
        pythonProcess = null;
    });
});

// Hàm đọc file CSV và gửi dữ liệu về renderer
function readAndSendResults() {
    const allPredictions = [];
    const suspiciousFlows = [];
    let totalThreats = 0;
    let criticalAlerts = 0;
    const readPromises = [];

    // Đọc file predictions tổng
    if (fs.existsSync(predictionsFile)) {
        readPromises.push(new Promise((resolve, reject) => {
            fs.createReadStream(predictionsFile)
                .pipe(csv())
                .on('data', (data) => allPredictions.push(data))
                .on('end', () => {
                    console.log(`Read ${allPredictions.length} rows from ${predictionsFile}`);
                    resolve();
                })
                .on('error', (error) => {
                    console.error(`Error reading ${predictionsFile}:`, error);
                    mainWindow.webContents.send('status-update', `Lỗi đọc file predictions: ${error.message}`);
                    reject(error);
                });
        }));
    } else {
        console.warn(`${predictionsFile} not found.`);
        mainWindow.webContents.send('status-update', `Không tìm thấy file kết quả tổng.`);
    }


    // Đọc file suspicious
    if (fs.existsSync(suspiciousFile)) {
        readPromises.push(new Promise((resolve, reject) => {
            fs.createReadStream(suspiciousFile)
                .pipe(csv())
                .on('data', (data) => {
                    suspiciousFlows.push(data);
                    totalThreats++; // Mỗi dòng trong file suspicious là 1 threat

                    // --- Logic xác định CRITICAL --- (Ví dụ)
                    const prediction = data.Prediction ? String(data.Prediction).toLowerCase() : '';
                    const probability = parseFloat(data.Prediction_Probability);
                    if (prediction.includes('critical') || (probability && probability > 0.9)) {
                        criticalAlerts++;
                    }
                    // ------------------------------
                })
                .on('end', () => {
                    console.log(`Read ${suspiciousFlows.length} rows from ${suspiciousFile}`);
                    resolve();
                })
                .on('error', (error) => {
                    console.error(`Error reading ${suspiciousFile}:`, error);
                    mainWindow.webContents.send('status-update', `Lỗi đọc file suspicious: ${error.message}`);
                    reject(error);
                });
        }));
    } else {
        console.warn(`${suspiciousFile} not found.`);
        mainWindow.webContents.send('status-update', `Không tìm thấy file luồng đáng ngờ.`);
    }

    // Sau khi đọc xong tất cả các file
    Promise.all(readPromises)
        .then(() => {
            // Gửi dữ liệu đã xử lý (bao gồm cả số liệu tính toán)
            mainWindow.webContents.send('results-data', {
                // all: allPredictions, // Không cần gửi nếu chỉ hiện suspicious
                suspicious: suspiciousFlows,
                totalThreats: totalThreats,
                criticalAlerts: criticalAlerts
            });
            mainWindow.webContents.send('status-update', 'Đã tải xong kết quả.');
        })
        .catch(error => {
            console.error("Error reading result files:", error);
            mainWindow.webContents.send('status-update', `Lỗi khi xử lý file kết quả.`);
        });

}


// In readAndSendResults function, add new files
const trafficAnalysisFile = path.join(resultsDir, 'traffic_analysis.csv');
const globalThreatMapFile = path.join(resultsDir, 'global_threat_map.csv');

function readAndSendResults() {
    const allPredictions = [];
    const suspiciousFlows = [];
    let totalThreats = 0;
    let criticalAlerts = 0;
    const readPromises = [];

    // Existing predictions and suspicious files
    if (fs.existsSync(predictionsFile)) {
        readPromises.push(new Promise((resolve, reject) => {
            fs.createReadStream(predictionsFile)
                .pipe(csv())
                .on('data', (data) => allPredictions.push(data))
                .on('end', resolve)
                .on('error', reject);
        }));
    }

    if (fs.existsSync(suspiciousFile)) {
        readPromises.push(new Promise((resolve, reject) => {
            fs.createReadStream(suspiciousFile)
                .pipe(csv())
                .on('data', (data) => {
                    suspiciousFlows.push(data);
                    totalThreats++;
                    const prediction = data.Prediction ? String(data.Prediction).toLowerCase() : '';
                    const probability = parseFloat(data.Prediction_Probability);
                    if (prediction.includes('critical') || (probability && probability > 0.9)) criticalAlerts++;
                })
                .on('end', resolve)
                .on('error', reject);
        }));
    }

    // New traffic analysis file
    const trafficData = [];
    if (fs.existsSync(trafficAnalysisFile)) {
        readPromises.push(new Promise((resolve, reject) => {
            fs.createReadStream(trafficAnalysisFile)
                .pipe(csv())
                .on('data', (data) => trafficData.push(data))
                .on('end', resolve)
                .on('error', reject);
        }));
    }

    // New global threat map file
    const threatMapData = [];
    if (fs.existsSync(globalThreatMapFile)) {
        readPromises.push(new Promise((resolve, reject) => {
            fs.createReadStream(globalThreatMapFile)
                .pipe(csv())
                .on('data', (data) => threatMapData.push(data))
                .on('end', resolve)
                .on('error', reject);
        }));
    }

    Promise.all(readPromises)
        .then(() => {
            mainWindow.webContents.send('results-data', {
                suspicious: suspiciousFlows,
                totalThreats: totalThreats,
                criticalAlerts: criticalAlerts,
                trafficAnalysis: trafficData.length > 0 ? trafficData[0] : { normal: 1423, suspicious: 62, malicious: 12 }, // Example
                globalThreatMap: threatMapData.length > 0 ? threatMapData[0] : { activeAttacks: 24, countries: 8, totalToday: 156 } // Example
            });
            mainWindow.webContents.send('status-update', 'Đã tải xong kết quả.');
        })
        .catch(error => {
            console.error("Error reading result files:", error);
            mainWindow.webContents.send('status-update', `Lỗi khi xử lý file kết quả.`);
        });
}