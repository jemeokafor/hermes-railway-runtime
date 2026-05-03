import childProcess from "node:child_process";
import fs from "node:fs";

import express from "express";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const READY_FILE = process.env.HERMES_READY_FILE ?? "/tmp/hermes-ready";
const GATEWAY_PID_FILE = process.env.HERMES_GATEWAY_PID_FILE ?? "/tmp/hermes-gateway.pid";
const OLLAMA_PID_FILE = process.env.HERMES_OLLAMA_PID_FILE ?? "/tmp/ollama.pid";
const START_SCRIPT = process.env.HERMES_START_SCRIPT ?? "/app/scripts/start-hermes-stack.sh";

let stackProc = null;
let restarting = false;
let shuttingDown = false;
let lastExit = null;

function readPid(file) {
  try {
    const value = fs.readFileSync(file, "utf8").trim();
    const pid = Number.parseInt(value, 10);
    return Number.isFinite(pid) ? pid : null;
  } catch {
    return null;
  }
}

function pidAlive(file) {
  const pid = readPid(file);
  if (!pid) return false;

  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function clearReady() {
  try {
    fs.rmSync(READY_FILE, { force: true });
  } catch {
    // ignore
  }
}

function launchStack() {
  if (stackProc || restarting || shuttingDown) return;

  clearReady();
  restarting = true;

  stackProc = childProcess.spawn("/bin/bash", [START_SCRIPT], {
    stdio: "inherit",
    env: process.env,
  });

  stackProc.on("spawn", () => {
    restarting = false;
    console.log(`[wrapper] launched Hermes stack pid=${stackProc.pid}`);
  });

  stackProc.on("error", (err) => {
    restarting = false;
    lastExit = {
      type: "error",
      message: String(err),
      at: new Date().toISOString(),
    };
    stackProc = null;
    clearReady();

    if (!shuttingDown) {
      setTimeout(launchStack, 5000).unref?.();
    }
  });

  stackProc.on("exit", (code, signal) => {
    lastExit = {
      type: "exit",
      code,
      signal,
      at: new Date().toISOString(),
    };
    stackProc = null;
    clearReady();
    console.error(`[wrapper] Hermes stack exited code=${code} signal=${signal}`);

    if (!shuttingDown) {
      setTimeout(launchStack, 5000).unref?.();
    }
  });
}

const app = express();
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => {
  const ready = fs.existsSync(READY_FILE);
  const gatewayAlive = pidAlive(GATEWAY_PID_FILE);
  const ollamaAlive = pidAlive(OLLAMA_PID_FILE);
  const ok = Boolean(ready && gatewayAlive && ollamaAlive && stackProc);

  res.status(ok ? 200 : 503).json({
    ok,
    ready,
    gatewayAlive,
    ollamaAlive,
    stackPid: stackProc?.pid ?? null,
    lastExit,
  });
});

app.get("/", (_req, res) => {
  const ready = fs.existsSync(READY_FILE);

  res.json({
    service: "hermes-railway-runtime",
    ready,
    gatewayAlive: pidAlive(GATEWAY_PID_FILE),
    ollamaAlive: pidAlive(OLLAMA_PID_FILE),
    stackPid: stackProc?.pid ?? null,
    lastExit,
  });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[wrapper] listening on :${PORT}`);
  launchStack();
});

process.on("SIGTERM", () => {
  shuttingDown = true;
  clearReady();

  try {
    stackProc?.kill("SIGTERM");
  } catch {
    // ignore
  }

  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref?.();
});
