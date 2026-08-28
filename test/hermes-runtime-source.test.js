import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { secureRead } from "../src/hermes-server.js";

const serverSrc = fs.readFileSync(new URL("../src/hermes-server.js", import.meta.url), "utf8");
const startScript = fs.readFileSync(new URL("../scripts/start-hermes-stack.sh", import.meta.url), "utf8");
const configureScript = fs.readFileSync(new URL("../scripts/configure-hermes.py", import.meta.url), "utf8");
const readinessScript = fs.readFileSync(
  new URL("../scripts/media-evidence-readiness.py", import.meta.url),
  "utf8",
);
const dockerfile = fs.readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");
const mediaPipeline = fs.readFileSync(new URL("../media_evidence/pipeline.py", import.meta.url), "utf8");
const mediaSandbox = fs.readFileSync(new URL("../media_evidence/sandbox.py", import.meta.url), "utf8");
const mediaCgroup = fs.readFileSync(new URL("../media_evidence/cgroup.py", import.meta.url), "utf8");
const mediaWorkerClient = fs.readFileSync(new URL("../media_evidence/worker_client.py", import.meta.url), "utf8");
const mediaPlugin = fs.readFileSync(new URL("../plugins/media-evidence/plugin.yaml", import.meta.url), "utf8");

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

test("health requires Ollama, the broker, and Hermes gateway", () => {
  assert.match(serverSrc, /const gatewayAlive = pidAlive\(GATEWAY_PID_FILE\)/);
  assert.match(serverSrc, /const ollamaAlive = pidAlive\(OLLAMA_PID_FILE\)/);
  assert.match(serverSrc, /const brokerAlive = pidAlive\(BROKER_PID_FILE\)/);
  assert.match(serverSrc, /const gatewayStatus = readJson\(GATEWAY_STATE_FILE/);
  assert.match(serverSrc, /platformIssue\(gatewayStatus\)/);
  assert.match(serverSrc, /health\.ok \? 200 : 503/);
});

test("media readiness producer and consumer share one path contract", () => {
  assert.match(serverSrc, /const SUPERVISOR_RUN_DIR = "\/run\/hermes-supervisor"/);
  assert.match(
    serverSrc,
    /MEDIA_EVIDENCE_READINESS_FILE[\s\S]*`\$\{SUPERVISOR_RUN_DIR\}\/media-evidence-readiness\.json`/,
  );
  assert.match(
    startScript,
    /MEDIA_EVIDENCE_READINESS_FILE="\$\{SUPERVISOR_RUN_DIR\}\/media-evidence-readiness\.json"/,
  );
  assert.match(startScript, /mv -f "\$\{temporary\}" "\$\{MEDIA_EVIDENCE_READINESS_FILE\}"/);
  assert.doesNotMatch(startScript, /HERMES_HOME.*media-evidence-readiness/);
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
  assert.match(startScript, /MEDIA_EVIDENCE_REQUIRE_READY/);
  assert.match(startScript, /check_media_evidence_readiness/);
  assert.match(startScript, /\/data\/workspace/);
  assert.match(startScript, /\/data\/media-evidence/);
  assert.match(startScript, /touch "\$\{HERMES_READY_FILE\}"/);
  assert.match(startScript, /HERMES_MANAGED=Railway/);
});

test("bootstrap classifies child exits and decouples Ollama restart", () => {
  assert.match(startScript, /STACK_STATE_FILE/);
  assert.match(startScript, /function write_stack_state|write_stack_state\(\)/);
  assert.match(startScript, /wait -n -p exited_pid/);
  assert.match(startScript, /"\$\{BROKER_PID\}"/);
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

test("runtime separates root supervisor and gateway-owned paths", () => {
  assert.match(startScript, /\/data\/\.hermes-supervisor/);
  assert.match(startScript, /\/run\/hermes-supervisor/);
  assert.match(configureScript, /Path\("\/data\/\.hermes"\)/);
  assert.match(configureScript, /Path\("\/data\/\.hermes-home"\)/);
  assert.match(configureScript, /Path\("\/data\/workspace"\)/);
  assert.match(configureScript, /os\.chown\(data, 0, 0/);
  assert.match(configureScript, /os\.chmod\(path, 0o700/);
  assert.match(
    configureScript,
    /Path\("\/data\/media-evidence"\),[\s\S]*mode=0o710,[\s\S]*required_uid=0,[\s\S]*required_gid=EVIDENCE_GID/,
  );
  assert.doesNotMatch(startScript, /BOOTSTRAP_LOG="\$\{HERMES_HOME\}/);
  assert.doesNotMatch(startScript, /STACK_STATE_FILE="\$\{HERMES_HOME\}/);
  assert.doesNotMatch(startScript, /MIGRATION_MARKER="\$\{HERMES_HOME\}/);
});

test("gateway commands use a fixed deprivileged setpriv boundary", () => {
  assert.match(startScript, /readonly GATEWAY_UID=23102/);
  assert.match(startScript, /readonly GATEWAY_GID=23102/);
  assert.match(startScript, /--clear-groups/);
  assert.match(startScript, /--no-new-privs/);
  assert.match(startScript, /--bounding-set=-all/);
  assert.match(startScript, /--inh-caps=-all/);
  assert.match(startScript, /--ambient-caps=-all/);
  assert.match(startScript, /--pdeathsig=SIGTERM/);
  assert.match(
    startScript,
    /"\$\{GATEWAY_PRIVILEGE\[@\]\}"[\s\S]*\/usr\/bin\/env -i "\$\{GATEWAY_ENV\[@\]\}"[\s\S]*configure-hermes\.py/,
  );
  assert.match(startScript, /GATEWAY_PRIVILEGE[\s\S]*hermes claw migrate/);
  assert.match(startScript, /GATEWAY_PRIVILEGE[\s\S]*python -m gateway\.run/);
  const gatewayEnvironment = startScript.match(/GATEWAY_ENV=\(([\s\S]*?)\n\)/)?.[1];
  assert.ok(gatewayEnvironment, "gateway environment allowlist must be explicit");
  for (const privilegedSetting of [
    "MEDIA_EVIDENCE_ROOT",
    "MEDIA_EVIDENCE_CGROUP_ROOT",
    "MEDIA_EVIDENCE_INPUT_ROOTS",
    "MEDIA_EVIDENCE_WHISPER_MODEL_PATH",
  ]) {
    assert.doesNotMatch(gatewayEnvironment, new RegExp(privilegedSetting));
  }
});

test("root broker receives only an explicit non-credential environment", () => {
  const brokerEnvironment = startScript.match(/BROKER_ENV=\(([\s\S]*?)\n\)/)?.[1];
  assert.ok(brokerEnvironment, "broker environment allowlist must be explicit");
  for (const credential of [
    "TELEGRAM_BOT_TOKEN",
    "CORTEX_MCP_BEARER_TOKEN",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "NVIDIA_API_KEY",
    "OLLAMA_API_KEY",
  ]) {
    assert.doesNotMatch(brokerEnvironment, new RegExp(credential));
  }
  assert.match(brokerEnvironment, /MEDIA_EVIDENCE_ROOT/);
  assert.match(brokerEnvironment, /MEDIA_EVIDENCE_CGROUP_ROOT/);
  assert.match(brokerEnvironment, /MEDIA_EVIDENCE_INPUT_ROOTS/);
  assert.match(brokerEnvironment, /MEDIA_EVIDENCE_WHISPER_MODEL_PATH/);
  assert.match(startScript, /\/usr\/bin\/env -i "\$\{BROKER_ENV\[@\]\}"/);
  assert.match(startScript, /python -I -m media_evidence\.broker/);
});

test("broker socket readiness and death are supervised", () => {
  assert.match(startScript, /start_media_evidence_broker\(\)/);
  assert.match(startScript, /\[ -S "\$\{MEDIA_EVIDENCE_BROKER_SOCKET\}" \]/);
  assert.match(startScript, /if \[ "\$\{exited_pid\}" = "\$\{BROKER_PID\}" \]/);
  assert.match(
    startScript,
    /rm -f "\$\{HERMES_READY_FILE\}" "\$\{MEDIA_EVIDENCE_READINESS_FILE\}"/,
  );
  assert.match(startScript, /stop_child "\$\{GATEWAY_PID:-\}"[\s\S]*stop_child "\$\{BROKER_PID:-\}"/);
});

test("readiness executes as the gateway and uses BrokerClient only", () => {
  assert.match(readinessScript, /from media_evidence\.broker_client import BrokerClient/);
  assert.match(readinessScript, /client\.capabilities\(\)/);
  assert.match(readinessScript, /client\.analyze\(/);
  assert.doesNotMatch(readinessScript, /MediaEvidencePipeline/);
  assert.match(
    startScript,
    /GATEWAY_PRIVILEGE[\s\S]*READINESS_ENV[\s\S]*media-evidence-readiness\.py[\s\S]*--socket/,
  );
});

test("offline ownership migration rejects unsafe and unbounded trees", () => {
  assert.match(configureScript, /MAX_OWNERSHIP_ENTRIES = 100_000/);
  assert.match(configureScript, /stat\.S_ISLNK/);
  assert.match(configureScript, /metadata\.st_nlink != 1/);
  assert.match(configureScript, /Unsafe ownership tree entry \(special file\)/);
  assert.match(configureScript, /stage_legacy_tree/);
  assert.match(configureScript, /collect_safe_ownership_tree\(source/);
});

test("wrapper safely reads files through validated descriptors", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-safe-read-"));
  try {
    const ownerUid = process.getuid();
    const regular = path.join(temporary, "state.json");
    fs.writeFileSync(regular, '{"ok":true}\n', { mode: 0o600 });
    assert.equal(
      secureRead(regular, { ownerUid, maxBytes: 1024 }).toString("utf8"),
      '{"ok":true}\n',
    );

    const symlink = path.join(temporary, "state-link");
    fs.symlinkSync(regular, symlink);
    assert.equal(secureRead(symlink, { ownerUid, maxBytes: 1024 }), null);

    const hardlink = path.join(temporary, "state-hardlink");
    fs.linkSync(regular, hardlink);
    assert.equal(secureRead(regular, { ownerUid, maxBytes: 1024 }), null);
    assert.equal(secureRead(hardlink, { ownerUid, maxBytes: 1024 }), null);

    const oversized = path.join(temporary, "oversized");
    fs.writeFileSync(oversized, "x".repeat(65));
    assert.equal(secureRead(oversized, { ownerUid, maxBytes: 64 }), null);
    assert.equal(secureRead(oversized, { ownerUid: ownerUid + 1, maxBytes: 1024 }), null);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  assert.match(serverSrc, /fs\.constants\.O_NOFOLLOW/);
  assert.match(serverSrc, /fs\.fstatSync\(descriptor\)/);
});

test("Dockerfile pins Hermes to an explicit upstream ref", () => {
  assert.match(dockerfile, /^FROM node:22-bookworm@sha256:[0-9a-f]{64}$/m);
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
  assert.match(dockerfile, /"python-telegram-bot": "22\.6"/);
  assert.match(dockerfile, /--extra messaging/);
});

test("Dockerfile does not patch over upstream redaction imports", () => {
  assert.match(dockerfile, /from agent\.redact import RedactingFormatter/);
});

test("Dockerfile patches Codex SDK terminal stream parsing", () => {
  assert.match(dockerfile, /Codex terminal SSE frame can omit response\.output/);
  assert.match(dockerfile, /responses\.stream helper/);
  assert.match(dockerfile, /_run_codex_create_stream_fallback/);
  assert.match(dockerfile, /from agent\.codex_runtime import run_codex_stream/);
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
  assert.match(dockerfile, /from agent\.codex_runtime import _consume_codex_event_stream/);
});

test("Dockerfile installs and freezes the media evidence worker", () => {
  for (const dependency of [
    "clamav",
    "clamav-freshclam",
    "ffmpeg",
    "libimage-exiftool-perl",
    "libseccomp2",
    "poppler-utils",
    "qpdf",
    "tesseract-ocr",
    "util-linux",
  ]) {
    assert.match(dockerfile, new RegExp(`\\b${dependency.replaceAll("-", "\\-")}\\b`));
  }
  assert.match(dockerfile, /useradd --system --uid "\$\{MEDIA_WORKER_UID\}" --gid hermes-media/);
  assert.match(dockerfile, /useradd --system --uid "\$\{MEDIA_ACQUISITION_UID\}" --gid hermes-acquire/);
  assert.match(dockerfile, /groupadd --system --gid 23102 hermes-gateway/);
  assert.match(dockerfile, /useradd --system --uid 23102 --gid hermes-gateway/);
  assert.match(dockerfile, /groupadd --system --gid 23103 hermes-evidence/);
  assert.match(dockerfile, /COPY media_evidence \/opt\/hermes-agent\/media_evidence/);
  assert.match(dockerfile, /COPY plugins\/media-evidence \/opt\/hermes-agent\/plugins\/media-evidence/);
  assert.match(dockerfile, /"faster-whisper": "1\.2\.1"/);
  assert.match(dockerfile, /WHISPER_MODEL_REVISION=3d3d5dee26484f91867d81cb899cfcf72b96be6c/);
  assert.match(dockerfile, /WHISPER_MODEL_SHA256=2a166925539a16005f14ff328359f9b9adb9dc4fb631bb3b227526862e93e2ef/);
  assert.match(dockerfile, /MEDIA_EVIDENCE_WHISPER_MODEL_PATH="\/opt\/media-models\/base\.en"/);
  assert.match(dockerfile, /npm ci --omit=dev/);
  assert.match(dockerfile, /"Pillow": "12\.2\.0"/);
  assert.match(dockerfile, /uv sync[\s\S]*--frozen[\s\S]*--no-dev[\s\S]*--extra voice/);
  assert.doesNotMatch(dockerfile, /uv pip install/);
  assert.match(dockerfile, /include = \["media_evidence", "media_evidence\.\*"/);
  assert.match(dockerfile, /\/opt\/hermes-venv\/bin\/python -I -c/);
  assert.match(dockerfile, /freshclam --stdout/);
  assert.match(dockerfile, /generate_media_sbom\.py/);
  assert.match(dockerfile, /scripts\/media-evidence-readiness\.py/);
  assert.match(dockerfile, /from media_evidence\.broker_client import BrokerClient/);
  assert.match(dockerfile, /runpy\.run_path\('\/app\/scripts\/media-evidence-readiness\.py'/);
  assert.match(dockerfile, /hermes-runtime\.cdx\.sha256/);
  assert.match(dockerfile, /chmod -R a-w \/opt\/hermes-agent\/media_evidence/);
});

test("media evidence remains opt-in and has no shell parser execution", () => {
  assert.match(mediaPlugin, /name: media-evidence/);
  assert.doesNotMatch(configureScript, /plugins[^\n]*media-evidence/);
  assert.doesNotMatch(mediaWorkerClient, /shell=True/);
  assert.doesNotMatch(mediaSandbox, /shell=True/);
  assert.match(mediaWorkerClient, /\/usr\/bin\/setpriv/);
  assert.match(mediaWorkerClient, /--result-fd/);
  assert.match(mediaWorkerClient, /pass_fds=/);
  assert.match(mediaPipeline, /content_trust.*untrusted/s);
  assert.match(mediaPipeline, /instruction_handling.*never_execute/s);
  assert.match(mediaPipeline, /os\.chown\(path, 0, self\.store\.worker_gid\)/);
});

test("media worker denies network and constrains filesystem access", () => {
  assert.match(mediaSandbox, /_DENIED_SYSCALLS/);
  assert.match(mediaSandbox, /"socket"/);
  assert.match(mediaSandbox, /"connect"/);
  assert.match(mediaSandbox, /"io_uring_setup"/);
  assert.match(mediaWorkerClient, /media_evidence\.supervisor/);
  assert.match(mediaSandbox, /restrict_filesystem/);
  assert.match(mediaSandbox, /_LANDLOCK_RULE_PATH_BENEATH/);
  assert.match(mediaSandbox, /RLIMIT_AS/);
  assert.match(mediaSandbox, /RLIMIT_FSIZE/);
  assert.match(mediaWorkerClient, /--cgroup/);
  assert.match(mediaCgroup, /"memory\.max"/);
  assert.match(mediaCgroup, /"pids\.max"/);
  assert.match(mediaCgroup, /"cpu\.max"/);
  assert.match(mediaCgroup, /cpu\.stat/);
  assert.match(mediaCgroup, /cgroup\.kill/);
});
