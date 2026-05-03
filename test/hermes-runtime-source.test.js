import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const serverSrc = fs.readFileSync(new URL("../src/hermes-server.js", import.meta.url), "utf8");
const startScript = fs.readFileSync(new URL("../scripts/start-hermes-stack.sh", import.meta.url), "utf8");
const configureScript = fs.readFileSync(new URL("../scripts/configure-hermes.py", import.meta.url), "utf8");

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
  assert.match(serverSrc, /ready && gatewayAlive && ollamaAlive && stackProc/);
});

test("bootstrap starts Ollama and the Hermes gateway", () => {
  assert.match(startScript, /ollama serve/);
  assert.match(startScript, /python -m gateway\.run/);
  assert.match(startScript, /touch "\$\{HERMES_READY_FILE\}"/);
});

test("configuration writes Hermes state and preserves legacy migration inputs", () => {
  assert.match(configureScript, /HERMES_HOME/);
  assert.match(configureScript, /config\.yaml/);
  assert.match(configureScript, /LEGACY_CONFIG_PATH/);
});
