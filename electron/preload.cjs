'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('greyiqDesktop', {
  platform: process.platform,
  // Opens the native folder picker; resolves to the chosen path or null.
  pickFolder: () => ipcRenderer.invoke('greyiq:pick-folder'),
  // Local-model GPU acceleration status: { vendor, runtime, accelerated }.
  gpuInfo: () => ipcRenderer.invoke('greyiq:gpu-info'),
});
