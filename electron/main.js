const { app, BrowserWindow, dialog, shell, ipcMain, Tray, Menu } = require('electron');
const { spawn, spawnSync } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');

if (require('electron-squirrel-startup')) app.quit();

const IS_DEV = !app.isPackaged;
// In packaged builds, Electron Forge's extraResource copies files directly
// into Contents/Resources/ — so PROJECT_ROOT is process.resourcesPath, not a subdirectory.
const PROJECT_ROOT = IS_DEV
  ? path.resolve(__dirname, '..')
  : process.resourcesPath;

let mainWindow = null;
let splashWindow = null;
let pythonProcess = null;
let serverPort = null;
let tray = null;
let isQuitting = false;

// ---------------------------------------------------------------------------
// Python discovery
// ---------------------------------------------------------------------------

function getPythonVersion(pythonPath) {
  try {
    const result = spawnSync(pythonPath, ['-c', 'import sys; v=sys.version_info; print(v.major,v.minor)'], { encoding: 'utf8', timeout: 5000 });
    if (result.status === 0 && result.stdout) {
      const parts = result.stdout.trim().split(' ').map(Number);
      return { major: parts[0], minor: parts[1] };
    }
  } catch { /* ignore */ }
  return null;
}

function isPythonCompatible(pythonPath) {
  const v = getPythonVersion(pythonPath);
  if (!v) return false;
  return v.major === 3 && v.minor >= 11 && v.minor <= 13;
}

function findPython() {
  const checked = [];

  const resolveCommandPath = (cmd) => {
    const checker = process.platform === 'win32' ? 'where' : 'which';
    const result = spawnSync(checker, [cmd], { encoding: 'utf8' });
    if (result.status === 0 && result.stdout) {
      const first = String(result.stdout).split('\n')[0].trim();
      if (first) return first;
    }
    return cmd;
  };

  const tryCandidate = (candidate) => {
    checked.push(candidate);
    try {
      if (candidate.includes(path.sep)) {
        if (fs.existsSync(candidate) && isPythonCompatible(candidate)) return candidate;
      } else {
        const resolved = resolveCommandPath(candidate);
        if (resolved && isPythonCompatible(resolved)) return resolved;
      }
    } catch { /* continue */ }
    return null;
  };

  // Prefer specific 3.11–3.13 versions first — explicit absolute paths for macOS GUI apps
  // where PATH is minimal and generic `python3` may resolve to an incompatible 3.14+.
  const candidates = process.platform === 'win32'
    ? [
        venvPythonDev,
        'python3.13', 'python3.12', 'python3.11', 'python',
      ]
    : [
        // Prefer the project venv first — guaranteed to have all dependencies installed
        venvPythonDev,
        '/opt/homebrew/bin/python3.13',
        '/opt/homebrew/bin/python3.12',
        '/opt/homebrew/bin/python3.11',
        '/usr/local/bin/python3.13',
        '/usr/local/bin/python3.12',
        '/usr/local/bin/python3.11',
        'python3.13', 'python3.12', 'python3.11',
        '/opt/homebrew/bin/python3',
        '/usr/local/bin/python3',
        '/usr/bin/python3',
        'python3',
      ];

  for (const candidate of candidates) {
    const resolved = tryCandidate(candidate);
    if (resolved) return { python: resolved, checked };
  }
  return { python: null, checked };
}

function runCommand(cmd, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`Command failed (${code}): ${cmd} ${args.join(' ')}\n${stderr || stdout}`));
      }
    });
  });
}

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function getVenvPythonPath(venvDir) {
  if (process.platform === 'win32') {
    return path.join(venvDir, 'Scripts', 'python.exe');
  }
  return path.join(venvDir, 'bin', 'python');
}

async function ensurePackagedBackendRuntime() {
  if (IS_DEV) return null;


  const requirementsPath = path.join(PROJECT_ROOT, 'requirements.txt');
  if (!fs.existsSync(requirementsPath)) {
    throw new Error(`Missing requirements file in packaged app: ${requirementsPath}`);
  }

  const { python: basePython, checked } = findPython();
  if (!basePython) {
    throw new Error(
      `No Python interpreter found for backend bootstrap.\nChecked: ${checked.join(', ')}\n` +
      'Install Python 3.11+ and reopen the app.',
    );
  }

  const runtimeRoot = path.join(app.getPath('userData'), 'backend-runtime');
  const venvDir = path.join(runtimeRoot, '.venv');
  const venvPython = getVenvPythonPath(venvDir);
  const reqHashPath = path.join(runtimeRoot, 'requirements.sha256');
  const pyVersionPath = path.join(runtimeRoot, 'python.version');
  const reqHash = sha256File(requirementsPath);
  const pyVersion = getPythonVersion(basePython);
  const pyVersionStr = pyVersion ? `${pyVersion.major}.${pyVersion.minor}` : 'unknown';

  const existingHash = fs.existsSync(reqHashPath) ? fs.readFileSync(reqHashPath, 'utf8').trim() : '';
  const existingPyVersion = fs.existsSync(pyVersionPath) ? fs.readFileSync(pyVersionPath, 'utf8').trim() : '';
  const venvReady = fs.existsSync(venvPython) && existingHash === reqHash && existingPyVersion === pyVersionStr;
  if (venvReady) return venvPython;

  fs.mkdirSync(runtimeRoot, { recursive: true });
  fs.rmSync(venvDir, { recursive: true, force: true });

  console.log(`[Electron] Bootstrapping backend runtime with: ${basePython}`);
  await runCommand(basePython, ['-m', 'venv', venvDir], { cwd: runtimeRoot, env: process.env });
  await runCommand(venvPython, ['-m', 'pip', 'install', '--upgrade', 'pip'], { cwd: PROJECT_ROOT, env: process.env });
  await runCommand(venvPython, ['-m', 'pip', 'install', '-r', requirementsPath], { cwd: PROJECT_ROOT, env: process.env });
  fs.writeFileSync(reqHashPath, reqHash, 'utf8');
  fs.writeFileSync(pyVersionPath, pyVersionStr, 'utf8');
  return venvPython;
}

// ---------------------------------------------------------------------------
// Backend lifecycle
// ---------------------------------------------------------------------------

function startBackend() {
  return new Promise((resolve, reject) => {
    const _start = async () => {
      const packagedRuntimePython = await ensurePackagedBackendRuntime();
      const discovered = findPython();
      const pythonExe = packagedRuntimePython || discovered.python;
      if (!pythonExe) {
        throw new Error(
          `Failed to find Python executable.\nChecked: ${discovered.checked.join(', ')}\n` +
          'Install Python 3.11+ and reopen the app.',
        );
      }
    const runScript = path.join(PROJECT_ROOT, 'run.py');
    const args = ['--port', '0'];

    const env = { ...process.env };
      env.PATH = path.dirname(pythonExe) + path.delimiter + (env.PATH || '');
    if (IS_DEV) {
      const venvSitePackages = path.join(PROJECT_ROOT, '.venv', 'lib');
      if (fs.existsSync(venvSitePackages)) {
        env.VIRTUAL_ENV = path.join(PROJECT_ROOT, '.venv');
        const venvBin = process.platform === 'win32' ? 'Scripts' : 'bin';
        env.PATH = path.join(PROJECT_ROOT, '.venv', venvBin) + path.delimiter + (env.PATH || '');
      }
    }

    console.log(`[Electron] Starting backend: ${pythonExe} ${runScript} ${args.join(' ')}`);

    pythonProcess = spawn(pythonExe, [runScript, ...args], {
      cwd: PROJECT_ROOT,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let portResolved = false;
    let stdoutBuffer = '';

    pythonProcess.stdout.on('data', (data) => {
      const text = data.toString();
      stdoutBuffer += text;

      if (!portResolved) {
        const lines = stdoutBuffer.split('\n');
        for (const line of lines) {
          try {
            const msg = JSON.parse(line.trim());
            if (msg.event === 'server_ready_port' && msg.port) {
              serverPort = msg.port;
              portResolved = true;
              console.log(`[Electron] Backend reported port: ${serverPort}`);
              waitForHealth(serverPort, 60000)
                .then(() => resolve(serverPort))
                .catch(reject);
              break;
            }
          } catch {
            // not JSON, normal log output
          }
        }
      }

      process.stdout.write(`[Backend] ${text}`);
    });

    pythonProcess.stderr.on('data', (data) => {
      const _t = data.toString();
      process.stderr.write(`[Backend:err] ${_t}`);
    });

    pythonProcess.on('error', (err) => {
      if (!portResolved) {
        reject(new Error(`Failed to start Python backend: ${err.message}`));
      }
    });

    pythonProcess.on('exit', (code) => {
      console.log(`[Electron] Backend exited with code ${code}`);
      pythonProcess = null;
      if (!isQuitting && mainWindow && !mainWindow.isDestroyed()) {
        dialog.showErrorBox(
          'Backend Stopped',
          `The AgenticTM backend process exited unexpectedly (code ${code}).\nThe application will close.`,
        );
        app.quit();
      }
    });

    setTimeout(() => {
      if (!portResolved) {
        reject(new Error('Backend did not report its port within 30 seconds'));
      }
    }, 30000);
    };

    _start().catch((err) => reject(err));
  });
}

function waitForHealth(port, timeoutMs) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    function check() {
      if (Date.now() - start > timeoutMs) {
        return reject(new Error('Backend health check timed out'));
      }
      const req = http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else {
          setTimeout(check, 500);
        }
      });
      req.on('error', () => setTimeout(check, 500));
      req.setTimeout(2000, () => {
        req.destroy();
        setTimeout(check, 500);
      });
    }
    check();
  });
}

function stopBackend() {
  if (!pythonProcess) return;
  console.log('[Electron] Stopping backend...');
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(pythonProcess.pid), '/f', '/t']);
    } else {
      pythonProcess.kill('SIGTERM');
      setTimeout(() => {
        if (pythonProcess) {
          try { pythonProcess.kill('SIGKILL'); } catch { /* already dead */ }
        }
      }, 5000);
    }
  } catch {
    // process already gone
  }
}

// ---------------------------------------------------------------------------
// Ollama check
// ---------------------------------------------------------------------------

function checkOllama() {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:11434/api/tags', (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(3000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

// ---------------------------------------------------------------------------
// Window management
// ---------------------------------------------------------------------------

function createSplashWindow() {
  splashWindow = new BrowserWindow({
    width: 480,
    height: 360,
    frame: false,
    transparent: false,
    resizable: false,
    alwaysOnTop: true,
    backgroundColor: '#1b1b1b',
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  const logoFilePath = path.join(PROJECT_ROOT, 'logo-philocyber.png');
  splashWindow.loadFile(path.join(__dirname, 'splash.html'), {
    query: { logoPath: logoFilePath },
  });
  splashWindow.once('ready-to-show', () => splashWindow.show());
}

function createMainWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#1b1b1b',
    show: false,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
  });

  mainWindow.loadURL(`http://127.0.0.1:${port}`);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.once('ready-to-show', () => {
    if (splashWindow && !splashWindow.isDestroyed()) {
      splashWindow.close();
      splashWindow = null;
    }
    mainWindow.show();
  });

  mainWindow.on('close', (e) => {
    if (!isQuitting && process.platform === 'darwin') {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

app.on('ready', async () => {
  createSplashWindow();

  try {
    const ollamaOk = await checkOllama();
    if (!ollamaOk) {
      const response = await dialog.showMessageBox(splashWindow, {
        type: 'warning',
        title: 'Ollama Not Detected',
        message: 'Ollama does not appear to be running.',
        detail:
          'AgenticTM requires Ollama for local LLM inference.\n\n' +
          'Please start Ollama and ensure it is listening on port 11434.\n' +
          'Download from: https://ollama.com',
        buttons: ['Continue Anyway', 'Open Ollama Website', 'Quit'],
        defaultId: 0,
        cancelId: 2,
      });

      if (response.response === 1) {
        shell.openExternal('https://ollama.com');
      }
      if (response.response === 2) {
        app.quit();
        return;
      }
    }

    const port = await startBackend();
    createMainWindow(port);
  } catch (err) {
    console.error('[Electron] Startup failed:', err);
    dialog.showErrorBox(
      'Startup Failed',
      `Could not start AgenticTM backend:\n\n${err.message}\n\nMake sure Python 3.11+ is installed and dependencies are available.`,
    );
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  stopBackend();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

ipcMain.handle('get-app-info', () => ({
  version: app.getVersion(),
  platform: process.platform,
  arch: process.arch,
  backendPort: serverPort,
}));

ipcMain.handle('open-external', (_, url) => {
  shell.openExternal(url);
});

ipcMain.handle('show-save-dialog', async (_, options) => {
  if (!mainWindow) return { canceled: true };
  return dialog.showSaveDialog(mainWindow, options);
});

ipcMain.handle('show-open-dialog', async (_, options) => {
  if (!mainWindow) return { canceled: true };
  return dialog.showOpenDialog(mainWindow, options);
});
