'use strict';

const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('greyiqDesktop', {
  platform: process.platform,
});
