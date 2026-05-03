import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");

test("wrapper schedules gateway recovery after failures", () => {
  assert.match(src, /function scheduleGatewayRecovery\(/);
  assert.match(src, /scheduleGatewayRecovery\("start failure"\)/);
  assert.match(src, /scheduleGatewayRecovery\("health probe"\)/);
});

test("wrapper can create a persistent startup volume backup", () => {
  assert.match(src, /OPENCLAW_CREATE_VOLUME_BACKUP/);
  assert.match(src, /async function createVolumeBackupIfRequested\(/);
  assert.match(src, /persistent snapshot ready/);
});
