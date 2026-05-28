# GreyIQ

A local-first AI chat playground that runs without cloud APIs or downloaded models. It includes:

- Editable bots with name, color, persona, style, and response variation.
- A small text-generation and response-ranking engine built from scratch in browser JavaScript.
- Personal training from preferences, example answers, and thumbs up/down feedback.
- CPU execution by default with optional WebGPU scoring for machines that expose a dedicated GPU to the browser.
- Local persistence through browser storage.

This is intentionally a tiny local learner, not a GPT-scale model. It is useful as a private, hackable base for persona tuning, preference learning, and local acceleration experiments.

## Run

```powershell
npm start
```

Open [http://localhost:4173](http://localhost:4173).

## Check

```powershell
npm run check
```

## How Training Works

Each bot owns a small hashed bag-of-words preference model. Preferences, examples, and response ratings become local training samples. The app trains a logistic scorer on the CPU, then uses either CPU or WebGPU to rank generated candidate replies. All training data stays in browser storage on the local machine.
