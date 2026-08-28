import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const HERMES_HOME = "/data/.hermes";
const SUPERVISOR_DATA_DIR = "/data/.hermes-supervisor";
const SUPERVISOR_RUN_DIR = "/run/hermes-supervisor";
const ROOT_UID = 0;
const GATEWAY_UID = 23102;
const READY_FILE = `${SUPERVISOR_RUN_DIR}/ready`;
const GATEWAY_PID_FILE = `${SUPERVISOR_RUN_DIR}/gateway.pid`;
const OLLAMA_PID_FILE = `${SUPERVISOR_RUN_DIR}/ollama.pid`;
const BROKER_PID_FILE = `${SUPERVISOR_RUN_DIR}/media-evidence-broker.pid`;
const START_SCRIPT = process.env.HERMES_START_SCRIPT ?? "/app/scripts/start-hermes-stack.sh";
const GATEWAY_STATE_FILE = `${HERMES_HOME}/gateway_state.json`;
const GATEWAY_LOG_FILE = `${SUPERVISOR_DATA_DIR}/logs/gateway-stdio.log`;
const STACK_STATE_FILE = `${SUPERVISOR_DATA_DIR}/stack_state.json`;
const PLANNED_STOP_DIAG_FILE = `${HERMES_HOME}/logs/planned-stop-markers.jsonl`;
const MEDIA_EVIDENCE_READINESS_FILE = `${SUPERVISOR_RUN_DIR}/media-evidence-readiness.json`;
const HEALTH_REQUIRE_TELEGRAM = !["0", "false", "no"].includes(
  (process.env.HERMES_HEALTH_REQUIRE_TELEGRAM ?? "true").toLowerCase(),
);
const HEALTH_REQUIRE_MEDIA_EVIDENCE = ["1", "true", "yes", "on"].includes(
  (process.env.MEDIA_EVIDENCE_REQUIRE_READY ?? "false").toLowerCase(),
);
const MEDIA_EVIDENCE_READINESS_MAX_AGE_MS = Number.parseInt(
  process.env.MEDIA_EVIDENCE_READINESS_MAX_AGE_MS ?? "28800000",
  10,
);
const SELF_HEAL_INTERVAL_MS = Number.parseInt(process.env.HERMES_SELF_HEAL_INTERVAL_MS ?? "30000", 10);
const SELF_HEAL_AFTER_MS = Number.parseInt(process.env.HERMES_SELF_HEAL_AFTER_MS ?? "120000", 10);
const requestedLogTailBytes = Number.parseInt(process.env.HERMES_HEALTH_LOG_TAIL_BYTES ?? "262144", 10);
const LOG_TAIL_BYTES = Number.isSafeInteger(requestedLogTailBytes)
  && requestedLogTailBytes > 0
  && requestedLogTailBytes <= 1024 * 1024
  ? requestedLogTailBytes
  : 262144;
const MAX_CONTROL_FILE_BYTES = 1024 * 1024;
const MAX_DIAGNOSTIC_FILE_BYTES = 128 * 1024 * 1024;

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

export function secureRead(file, { ownerUid, maxBytes, tailBytes = null }) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | fs.constants.O_NOFOLLOW,
    );
    const before = fs.fstatSync(descriptor);
    if (
      !before.isFile()
      || before.uid !== ownerUid
      || before.nlink !== 1
      || !Number.isSafeInteger(before.size)
      || before.size < 0
      || before.size > maxBytes
    ) {
      return null;
    }

    const requestedTail = tailBytes === null ? before.size : Math.min(before.size, tailBytes);
    const start = before.size - requestedTail;
    const buffer = Buffer.alloc(requestedTail);
    let offset = 0;
    while (offset < requestedTail) {
      const bytesRead = fs.readSync(
        descriptor,
        buffer,
        offset,
        requestedTail - offset,
        start + offset,
      );
      if (bytesRead === 0) return null;
      offset += bytesRead;
    }

    const after = fs.fstatSync(descriptor);
    if (
      !after.isFile()
      || after.uid !== ownerUid
      || after.nlink !== 1
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.size < before.size
      || (tailBytes === null && after.size !== before.size)
    ) {
      return null;
    }
    return buffer;
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readPid(file) {
  const content = secureRead(file, { ownerUid: ROOT_UID, maxBytes: 64 });
  if (!content) return null;
  const value = content.toString("utf8").trim();
  if (!/^[1-9][0-9]{0,9}$/.test(value)) return null;
  const pid = Number.parseInt(value, 10);
  return Number.isSafeInteger(pid) ? pid : null;
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

function readJson(file, ownerUid, maxBytes = MAX_CONTROL_FILE_BYTES) {
  try {
    const content = secureRead(file, { ownerUid, maxBytes });
    return content ? JSON.parse(content.toString("utf8")) : null;
  } catch {
    return null;
  }
}

function readLastJsonLine(file, ownerUid) {
  const text = readTail(file, 65536, ownerUid);
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
      broker: safeNumber(logBytes.broker),
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

function readTail(file, maxBytes, ownerUid) {
  const content = secureRead(file, {
    ownerUid,
    maxBytes: MAX_DIAGNOSTIC_FILE_BYTES,
    tailBytes: maxBytes,
  });
  return content?.toString("utf8") ?? "";
}

function lastLogMatch(patterns) {
  const text = readTail(GATEWAY_LOG_FILE, LOG_TAIL_BYTES, ROOT_UID);
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

function mediaEvidenceReadiness() {
  if (!HEALTH_REQUIRE_MEDIA_EVIDENCE) return { issue: null, record: null };
  const record = readJson(MEDIA_EVIDENCE_READINESS_FILE, ROOT_UID);
  if (!record || typeof record !== "object") {
    return { issue: "media_evidence_readiness_missing", record: null };
  }
  if (record.ok !== true) {
    return { issue: "media_evidence_readiness_failed", record };
  }
  const checkedAt = Number(record.checked_at_epoch) * 1000;
  const age = Date.now() - checkedAt;
  if (!Number.isFinite(checkedAt) || age < -300000 || age > MEDIA_EVIDENCE_READINESS_MAX_AGE_MS) {
    return { issue: "media_evidence_readiness_stale", record };
  }
  return { issue: null, record };
}

function currentHealth() {
  const ready = secureRead(READY_FILE, { ownerUid: ROOT_UID, maxBytes: 64 }) !== null;
  const gatewayAlive = pidAlive(GATEWAY_PID_FILE);
  const ollamaAlive = pidAlive(OLLAMA_PID_FILE);
  const brokerAlive = pidAlive(BROKER_PID_FILE);
  const gatewayStatus = readJson(GATEWAY_STATE_FILE, GATEWAY_UID);
  const stackState = sanitizeStackState(readJson(STACK_STATE_FILE, ROOT_UID));
  const plannedStop = sanitizePlannedStopDiag(
    readLastJsonLine(PLANNED_STOP_DIAG_FILE, GATEWAY_UID),
  );
  const gatewayState = gatewayStatus?.gateway_state ?? null;
  const telegram = gatewayStatus?.platforms?.telegram ?? null;
  const issues = [];
  const restartableIssues = [];
  const codexAuthFailure = lastLogMatch(AUTH_FAILURE_PATTERNS);
  const mediaEvidence = mediaEvidenceReadiness();

  if (!ready) issues.push("not_ready");
  if (!gatewayAlive) issues.push("gateway_process_dead");
  if (!ollamaAlive) issues.push("ollama_process_dead");
  if (!brokerAlive) issues.push("media_evidence_broker_process_dead");
  if (!stackProc) issues.push("stack_process_missing");

  const platformProblem = platformIssue(gatewayStatus);
  if (platformProblem) {
    issues.push(platformProblem);
    restartableIssues.push(platformProblem);
  }

  if (codexAuthFailure) {
    issues.push("codex_auth_failure");
  }
  if (mediaEvidence.issue) {
    issues.push(mediaEvidence.issue);
    restartableIssues.push(mediaEvidence.issue);
  }

  const ok = Boolean(
    ready
      && gatewayAlive
      && ollamaAlive
      && brokerAlive
      && stackProc
      && !platformProblem
      && !mediaEvidence.issue,
  );

  return {
    ok,
    ready,
    gatewayAlive,
    ollamaAlive,
    brokerAlive,
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
    mediaEvidence: mediaEvidence.record
      ? {
          ok: mediaEvidence.record.ok === true,
          checkedAtEpoch: safeNumber(Number(mediaEvidence.record.checked_at_epoch)),
          canaryJobId: typeof mediaEvidence.record.canary_job_id === "string"
            ? mediaEvidence.record.canary_job_id
            : null,
          failures: Array.isArray(mediaEvidence.record.failures)
            ? mediaEvidence.record.failures.slice(0, 20).map((value) => String(value).slice(0, 160))
            : [],
        }
      : null,
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
  if (
    !health.ready
    || !health.gatewayAlive
    || !health.ollamaAlive
    || !health.brokerAlive
    || !reason
  ) {
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

function startHttpServer() {
  if (typeof process.getuid !== "function" || process.getuid() !== ROOT_UID) {
    throw new Error("Hermes supervisor must run as root");
  }
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
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startHttpServer();
}
