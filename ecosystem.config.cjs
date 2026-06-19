const { spawnSync } = require("node:child_process");

function commandWorks(script, args = []) {
  const result = spawnSync(script, [...args, "--version"], {
    stdio: "ignore",
    shell: false,
  });
  return result.status === 0;
}

function resolvePythonCommand() {
  const configured = [process.env.GREYIQ_PYTHON, process.env.PYTHON]
    .filter(Boolean)
    .map((script) => ({ script, args: [] }));
  const defaults =
    process.platform === "win32"
      ? [
          { script: "python", args: [] },
          { script: "py", args: ["-3"] },
          { script: "python3", args: [] },
        ]
      : [
          { script: "python3", args: [] },
          { script: "python", args: [] },
        ];

  for (const candidate of [...configured, ...defaults]) {
    if (commandWorks(candidate.script, candidate.args)) {
      return candidate;
    }
  }

  return process.platform === "win32"
    ? { script: "python", args: [] }
    : { script: "python3", args: [] };
}

const backendPython = resolvePythonCommand();
const commonEnv = {
  NODE_ENV: "production",
};

module.exports = {
  apps: [
    {
      name: "greyiq-web",
      script: "server.mjs",
      cwd: __dirname,
      time: true,
      env: {
        ...commonEnv,
        HOST: "127.0.0.1",
        PORT: "4173",
      },
    },
    {
      name: "greyiq-api",
      script: backendPython.script,
      args: [...backendPython.args, "-m", "backend.greyiq_api"].join(" "),
      interpreter: "none",
      cwd: __dirname,
      time: true,
      env: {
        ...commonEnv,
        GREYIQ_HOST: "127.0.0.1",
        GREYIQ_PORT: "8766",
        GREYIQ_RUNTIME_DIR: process.env.GREYIQ_RUNTIME_DIR || "runtime",
      },
    },
  ],
};
