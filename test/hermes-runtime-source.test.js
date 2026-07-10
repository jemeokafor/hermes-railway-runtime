import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const serverSrc = fs.readFileSync(new URL("../src/hermes-server.js", import.meta.url), "utf8");
const startScript = fs.readFileSync(new URL("../scripts/start-hermes-stack.sh", import.meta.url), "utf8");
const configureScript = fs.readFileSync(new URL("../scripts/configure-hermes.py", import.meta.url), "utf8");
const dockerfile = fs.readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");

test("wrapper exposes Railway health and identity endpoints", () => {
  assert.match(serverSrc, /app\.get\("\/healthz"/);
  assert.match(serverSrc, /app\.get\("\/"/);
  assert.match(serverSrc, /service: "hermes-railway-runtime"/);
});

test("wrapper supervises the Hermes stack process", () => {
  assert.match(serverSrc, /const START_SCRIPT = .*start-hermes-stack\.sh/);
  assert.match(serverSrc, /childProcess\.spawn\("\/bin\/bash", \[START_SCRIPT\]/);
  assert.match(serverSrc, /setTimeout\(launchStack, 5000\)/);
});

test("health requires both Ollama and Hermes gateway", () => {
  assert.match(serverSrc, /const gatewayAlive = pidAlive\(GATEWAY_PID_FILE\)/);
  assert.match(serverSrc, /const ollamaAlive = pidAlive\(OLLAMA_PID_FILE\)/);
  assert.match(serverSrc, /const gatewayStatus = readJson\(GATEWAY_STATE_FILE\)/);
  assert.match(serverSrc, /platformIssue\(gatewayStatus\)/);
  assert.match(serverSrc, /health\.ok \? 200 : 503/);
});

test("health surfaces auth failures without making them restartable", () => {
  assert.match(serverSrc, /AUTH_FAILURE_PATTERNS/);
  assert.match(serverSrc, /codexAuthFailure = lastLogMatch\(AUTH_FAILURE_PATTERNS\)/);
  assert.match(serverSrc, /issues\.push\("codex_auth_failure"\)/);
  assert.doesNotMatch(serverSrc, /restartableIssues\.push\("codex_auth_failure"\)/);
});

test("wrapper self-heals restartable platform failures", () => {
  assert.match(serverSrc, /function checkSelfHeal\(\)/);
  assert.match(serverSrc, /restartStack\(reason\)/);
  assert.match(serverSrc, /setInterval\(checkSelfHeal, SELF_HEAL_INTERVAL_MS\)/);
});

test("health exposes sanitized stack diagnostics", () => {
  assert.match(serverSrc, /const STACK_STATE_FILE/);
  assert.match(serverSrc, /sanitizeStackState/);
  assert.match(serverSrc, /lastChildExit: stackState\?\.lastChildExit/);
  assert.match(serverSrc, /oomKillCount/);
  assert.match(serverSrc, /sanitizePlannedStopDiag/);
  assert.doesNotMatch(serverSrc, /stopper_cmdline/);
  assert.doesNotMatch(serverSrc, /stopper_parent_cmdline/);
});

test("bootstrap starts Ollama and the Hermes gateway", () => {
  assert.match(startScript, /ollama serve/);
  assert.match(startScript, /python -m gateway\.run/);
  assert.match(startScript, /touch "\$\{HERMES_READY_FILE\}"/);
});

test("bootstrap classifies child exits and decouples Ollama restart", () => {
  assert.match(startScript, /STACK_STATE_FILE/);
  assert.match(startScript, /function write_stack_state|write_stack_state\(\)/);
  assert.match(startScript, /wait -n -p exited_pid/);
  assert.match(startScript, /restart_ollama/);
  assert.match(startScript, /without stopping gateway/);
  assert.match(startScript, /lastChildExit/);
  assert.match(startScript, /rotate_logs/);
});

test("configuration writes Hermes state and preserves legacy migration inputs", () => {
  assert.match(configureScript, /HERMES_HOME/);
  assert.match(configureScript, /config\.yaml/);
  assert.match(configureScript, /LEGACY_CONFIG_PATH/);
});

test("Dockerfile pins Hermes to an explicit upstream ref", () => {
  assert.match(dockerfile, /ARG HERMES_GIT_REF=2bd1977d8fad185c9b4be47884f7e87f1add0ce3/);
  assert.match(dockerfile, /git fetch --depth 1 origin "\$\{HERMES_GIT_REF\}"/);
  assert.doesNotMatch(dockerfile, /git clone --depth 1 --branch main/);
});

test("Dockerfile applies the Telegram RetryAfter delivery patch", () => {
  const retryPatch = fs.readFileSync(
    new URL("../scripts/patch-hermes-telegram-retry.py", import.meta.url),
    "utf8",
  );

  assert.match(dockerfile, /COPY scripts\/patch-hermes-telegram-retry\.py/);
  assert.match(dockerfile, /python3 \/tmp\/patch-hermes-telegram-retry\.py/);
  assert.match(retryPatch, /retry_after_seconds/);
  assert.match(retryPatch, /server_delay/);
  assert.match(retryPatch, /sendRichMessage transient failure/);
});

test("Dockerfile keeps Telegram available without runtime lazy installs", () => {
  assert.match(dockerfile, /python-telegram-bot\[webhooks\]==22\.6/);
});

test("Dockerfile does not patch over upstream redaction imports", () => {
  assert.match(dockerfile, /from agent\.redact import RedactingFormatter/);
});

test("Dockerfile patches Codex SDK terminal stream parsing", () => {
  assert.match(dockerfile, /Codex terminal SSE frame can omit response\.output/);
  assert.match(dockerfile, /responses\.stream helper/);
  assert.match(dockerfile, /_run_codex_create_stream_fallback/);
});

test("Dockerfile preserves planned-stop marker source diagnostics", () => {
  assert.match(dockerfile, /Railway planned-stop marker source diagnostics/);
  assert.match(dockerfile, /planned-stop-markers\.jsonl/);
  assert.match(dockerfile, /_append_planned_stop_marker_diag/);
  assert.match(dockerfile, /stopper_cmdline/);
  assert.match(dockerfile, /stopper_parent_cmdline/);
});

test("Dockerfile patches auxiliary Codex streaming", () => {
  assert.match(dockerfile, /Codex auxiliary avoids responses\.stream parser/);
  assert.match(dockerfile, /responses\.create\(\*\*_stream_kwargs\)/);
  assert.match(dockerfile, /terminal_response or SimpleNamespace\(output=\[\]\)/);
});
