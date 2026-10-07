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

// Bind the same fixed controls on the app and on the local data: startup/error
// pages. Those pages deliberately disallow page scripts through their CSP, while
// the preload still has the narrow IPC access required to close a failed window.
function installWindowControls() {
  const titlebar = document.querySelector('[data-window-titlebar]');
  if (!titlebar) return;
  titlebar.hidden = false;
  document.body.classList.add('desktop-window');

  const maximizeButton = titlebar.querySelector('[data-window-control="maximize"]');
  const setMaximized = (maximized) => {
    if (!maximizeButton) return;
    const active = Boolean(maximized);
    maximizeButton.classList.toggle('is-maximized', active);
    const label = `${active ? 'Restore' : 'Maximize'} GreyIQ`;
    maximizeButton.setAttribute('aria-label', label);
    maximizeButton.title = label;
  };
  ipcRenderer.on('greyiq:window-maximized', (_event, maximized) => setMaximized(maximized));
  void ipcRenderer.invoke('greyiq:window-is-maximized').then(setMaximized).catch(() => {});

  const channels = {
    minimize: 'greyiq:window-minimize',
    maximize: 'greyiq:window-toggle-maximize',
    close: 'greyiq:window-close',
  };
  for (const button of titlebar.querySelectorAll('[data-window-control]')) {
    const channel = channels[button.getAttribute('data-window-control')];
    if (!channel) continue;
    button.addEventListener('click', () => {
      void ipcRenderer.invoke(channel).then((result) => {
        if (channel === channels.maximize) setMaximized(result);
      }).catch(() => {});
    });
  }
}

if (document.readyState === 'loading') {
  window.addEventListener('DOMContentLoaded', installWindowControls, { once: true });
} else {
  installWindowControls();
}
