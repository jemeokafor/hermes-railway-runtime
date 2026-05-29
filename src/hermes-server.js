import childProcess from "node:child_process";
import fs from "node:fs";

import express from "express";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const HERMES_HOME = process.env.HERMES_HOME ?? "/data/.hermes";
const READY_FILE = process.env.HERMES_READY_FILE ?? "/tmp/hermes-ready";
const GATEWAY_PID_FILE = process.env.HERMES_GATEWAY_PID_FILE ?? "/tmp/hermes-gateway.pid";
const OLLAMA_PID_FILE = process.env.HERMES_OLLAMA_PID_FILE ?? "/tmp/ollama.pid";
const START_SCRIPT = process.env.HERMES_START_SCRIPT ?? "/app/scripts/start-hermes-stack.sh";
const GATEWAY_STATE_FILE = process.env.HERMES_GATEWAY_STATE_FILE ?? `${HERMES_HOME}/gateway_state.json`;
const GATEWAY_LOG_FILE = process.env.HERMES_GATEWAY_LOG_FILE ?? `${HERMES_HOME}/logs/gateway.log`;
const STACK_STATE_FILE = process.env.HERMES_STACK_STATE_FILE ?? `${HERMES_HOME}/stack_state.json`;
const PLANNED_STOP_DIAG_FILE = process.env.HERMES_PLANNED_STOP_DIAG_FILE
  ?? `${HERMES_HOME}/logs/planned-stop-markers.jsonl`;
const HEALTH_REQUIRE_TELEGRAM = !["0", "false", "no"].includes(
  (process.env.HERMES_HEALTH_REQUIRE_TELEGRAM ?? "true").toLowerCase(),
);
const SELF_HEAL_INTERVAL_MS = Number.parseInt(process.env.HERMES_SELF_HEAL_INTERVAL_MS ?? "30000", 10);
const SELF_HEAL_AFTER_MS = Number.parseInt(process.env.HERMES_SELF_HEAL_AFTER_MS ?? "120000", 10);
const LOG_TAIL_BYTES = Number.parseInt(process.env.HERMES_HEALTH_LOG_TAIL_BYTES ?? "262144", 10);

let stackProc = null;
let restarting = false;
let shuttingDown = false;
let lastExit = null;
let lastSelfHeal = null;
let unhealthySince = null;

const AUTH_FAILURE_PATTERNS = [
  /Codex refresh token was already consumed/i,
  /no Codex OAuth token found/i,
  /Primary provider auth failed/i,
];

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

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function readLastJsonLine(file) {
  const text = readTail(file, 65536);
  if (!text) return null;

  const lines = text.split("\n").filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      return JSON.parse(lines[index]);
    } catch {
      // keep scanning older lines
    }
  }

  return null;
}

function safeNumber(value) {
  return Number.isFinite(value) ? value : null;
}

function sanitizeStackState(stackState) {
  if (!stackState || typeof stackState !== "object") return null;

  const resources = stackState.resources && typeof stackState.resources === "object"
    ? stackState.resources
    : {};
  const memoryEvents = resources.memoryEvents && typeof resources.memoryEvents === "object"
    ? resources.memoryEvents
    : {};
  const logBytes = stackState.logBytes && typeof stackState.logBytes === "object"
    ? stackState.logBytes
    : {};
  const lastChildExit = stackState.lastChildExit && typeof stackState.lastChildExit === "object"
    ? stackState.lastChildExit
    : null;

  return {
    event: stackState.event ?? null,
    action: stackState.action ?? null,
    updatedAt: stackState.updatedAt ?? null,
    lastChildExit: lastChildExit
      ? {
          child: lastChildExit.child ?? null,
          pid: safeNumber(lastChildExit.pid),
          status: safeNumber(lastChildExit.status),
          signal: lastChildExit.signal ?? null,
          at: lastChildExit.at ?? null,
        }
      : null,
    resources: {
      memoryCurrentMb: safeNumber(resources.memoryCurrentMb),
      memoryMaxMb: safeNumber(resources.memoryMaxMb),
      pidsCurrent: safeNumber(resources.pidsCurrent),
      pidsMax: safeNumber(resources.pidsMax),
      load1: safeNumber(resources.load1),
      load5: safeNumber(resources.load5),
      load15: safeNumber(resources.load15),
      dataUsedPct: safeNumber(resources.dataUsedPct),
      oomKillCount: safeNumber(memoryEvents.oom_kill),
      oomCount: safeNumber(memoryEvents.oom),
    },
    logBytes: {
      bootstrap: safeNumber(logBytes.bootstrap),
      gateway: safeNumber(logBytes.gateway),
      ollama: safeNumber(logBytes.ollama),
    },
  };
}

function sanitizePlannedStopDiag(diag) {
  if (!diag || typeof diag !== "object") return null;

  const marker = diag.marker && typeof diag.marker === "object" ? diag.marker : {};
  return {
    observedAt: diag.observed_at ?? null,
    matched: typeof diag.matched === "boolean" ? diag.matched : null,
    reason: diag.reason ?? null,
    targetPid: safeNumber(marker.target_pid),
    stopperPid: safeNumber(marker.stopper_pid),
    stopperPpid: safeNumber(marker.stopper_ppid),
    writtenAt: marker.written_at ?? null,
  };
}

function readTail(file, maxBytes) {
  try {
    const stat = fs.statSync(file);
    const start = Math.max(0, stat.size - maxBytes);
    const length = stat.size - start;
    const buffer = Buffer.alloc(length);
    const fd = fs.openSync(file, "r");
    try {
      fs.readSync(fd, buffer, 0, length, start);
    } finally {
      fs.closeSync(fd);
    }
    return buffer.toString("utf8");
  } catch {
    return "";
  }
}

function lastLogMatch(patterns) {
  const text = readTail(GATEWAY_LOG_FILE, LOG_TAIL_BYTES);
  if (!text) return null;

  const lines = text.split("\n");
  const lastStartupIndex = Math.max(
    lines.findLastIndex((line) => line.includes("Connected to Telegram")),
    lines.findLastIndex((line) => line.includes("Gateway running")),
  );

  for (let index = lines.length - 1; index > lastStartupIndex; index -= 1) {
    const line = lines[index];
    if (patterns.some((pattern) => pattern.test(line))) {
      return {
        line: line.slice(0, 500),
        sinceLastStartup: lastStartupIndex >= 0,
      };
    }
  }

  return null;
}

function platformIssue(gatewayStatus) {
  if (!HEALTH_REQUIRE_TELEGRAM) return null;

  const telegram = gatewayStatus?.platforms?.telegram;
  if (!telegram) {
    return "telegram_status_missing";
  }

  if (telegram.state !== "connected") {
    return `telegram_${telegram.state ?? "unknown"}`;
  }

  return null;
}

function currentHealth() {
  const ready = fs.existsSync(READY_FILE);
  const gatewayAlive = pidAlive(GATEWAY_PID_FILE);
  const ollamaAlive = pidAlive(OLLAMA_PID_FILE);
  const gatewayStatus = readJson(GATEWAY_STATE_FILE);
  const stackState = sanitizeStackState(readJson(STACK_STATE_FILE));
  const plannedStop = sanitizePlannedStopDiag(readLastJsonLine(PLANNED_STOP_DIAG_FILE));
  const gatewayState = gatewayStatus?.gateway_state ?? null;
  const telegram = gatewayStatus?.platforms?.telegram ?? null;
  const issues = [];
  const restartableIssues = [];
  const codexAuthFailure = lastLogMatch(AUTH_FAILURE_PATTERNS);

  if (!ready) issues.push("not_ready");
  if (!gatewayAlive) issues.push("gateway_process_dead");
  if (!ollamaAlive) issues.push("ollama_process_dead");
  if (!stackProc) issues.push("stack_process_missing");

  const platformProblem = platformIssue(gatewayStatus);
  if (platformProblem) {
    issues.push(platformProblem);
    restartableIssues.push(platformProblem);
  }

  if (codexAuthFailure) {
    issues.push("codex_auth_failure");
  }

  const ok = Boolean(
    ready
      && gatewayAlive
      && ollamaAlive
      && stackProc
      && !platformProblem,
  );

  return {
    ok,
    ready,
    gatewayAlive,
    ollamaAlive,
    stackPid: stackProc?.pid ?? null,
    gatewayState,
    telegram: telegram
      ? {
          state: telegram.state ?? null,
          errorCode: telegram.error_code ?? null,
          errorMessage: telegram.error_message ?? null,
          updatedAt: telegram.updated_at ?? null,
        }
      : null,
    codexAuthFailure,
    issues,
    restartableIssues,
    lastExit,
    lastSelfHeal,
    stack: stackState,
    lastChildExit: stackState?.lastChildExit ?? null,
    lastPlannedStop: plannedStop,
  };
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

function restartStack(reason) {
  if (!stackProc || restarting || shuttingDown) return;

  lastSelfHeal = {
    reason,
    at: new Date().toISOString(),
  };
  console.error(`[wrapper] self-healing Hermes stack reason=${reason}`);
  clearReady();

  try {
    stackProc.kill("SIGTERM");
  } catch (err) {
    console.error(`[wrapper] failed to stop Hermes stack for self-heal: ${err}`);
  }
}

function checkSelfHeal() {
  if (shuttingDown || restarting) return;

  const health = currentHealth();
  const reason = health.restartableIssues[0];
  if (!health.ready || !health.gatewayAlive || !health.ollamaAlive || !reason) {
    unhealthySince = null;
    return;
  }

  const now = Date.now();
  unhealthySince ??= now;
  if (now - unhealthySince >= SELF_HEAL_AFTER_MS) {
    unhealthySince = null;
    restartStack(reason);
  }
}

const app = express();
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => {
  const health = currentHealth();

  res.status(health.ok ? 200 : 503).json(health);
});

app.get("/", (_req, res) => {
  res.json({
    service: "hermes-railway-runtime",
    ...currentHealth(),
  });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[wrapper] listening on :${PORT}`);
  launchStack();
  if (Number.isFinite(SELF_HEAL_INTERVAL_MS) && SELF_HEAL_INTERVAL_MS > 0) {
    setInterval(checkSelfHeal, SELF_HEAL_INTERVAL_MS).unref?.();
  }
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
