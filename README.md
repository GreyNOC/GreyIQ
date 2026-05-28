# GreyIQ

GreyIQ is a soft, friendly, powerful local AI chat app. It stays separate from the GreyNOC SOC interface and runs as its own GreyIQ desktop/web experience.

It includes:

- Editable bots with name, color, persona, style, and response variation.
- Imported local engine runtime from AiFace, with CPU/CUDA device preference.
- Personal training from preferences, source-specific training data, and thumbs up/down feedback.
- AI core store wiring for bot/core metadata, trust contracts, starter knowledge, and local training sources.
- Browser fallback with CPU/WebGPU scoring when the Python service is not running.
- Electron launcher that starts the GreyIQ backend and opens the chat UI.

## Run

Browser-only fallback:

```powershell
npm start
```

Open [http://localhost:4173](http://localhost:4173).

Full local engine:

```powershell
python -m backend.greyiq_api
```

Open [http://localhost:8766](http://localhost:8766).

Desktop:

```powershell
npm install
npm run desktop
```

## Check

```powershell
npm run check
```

## How Training Works

Each bot owns browser-side preference weights for instant fallback behavior. When the GreyIQ backend is running, preferences, rated examples, and source-specific training data are also written into the local runtime training data. The trainer can run against one or more selected sources, and the AI core store tracks the active bot as a local core. Data stays on the machine unless you explicitly move it.

## AI Cores

GreyIQ starts with companion, builder, and researcher cores. Each core carries a response contract, confidence policy, trust posture, and starter knowledge profile so first-run answers feel useful before personal training begins. Personal choices and imported documents become higher-priority local sources as the user trains the app.
