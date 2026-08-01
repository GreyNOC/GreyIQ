'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('greyiqDesktop', {
  platform: process.platform,
  // Opens the native folder picker; resolves to the chosen path or null.
  pickFolder: () => ipcRenderer.invoke('greyiq:pick-folder'),
  // Local-model GPU acceleration status: { vendor, runtime, accelerated }.
  gpuInfo: () => ipcRenderer.invoke('greyiq:gpu-info'),
  // Provision (download on first use) + start the on-demand Ollama runtime when the
  // user selects the local model. Resolves { ok, runtime } or { ok: false, error }.
  ensureOllama: () => ipcRenderer.invoke('greyiq:ensure-ollama'),
  // Launch the companion TACNOC desktop application through the main process's
  // fixed-path discovery. The renderer never supplies an executable or arguments.
  launchTacnoc: () => ipcRenderer.invoke('greyiq:launch-tacnoc'),
});
