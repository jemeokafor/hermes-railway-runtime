import { spawnSync } from "node:child_process";

// Basic sanity: ensure the Hermes CLI exists in the built image.
const r = spawnSync("hermes", ["--version"], { encoding: "utf8" });
if (r.status !== 0) {
  console.error(r.stdout || r.stderr);
  process.exit(r.status ?? 1);
}
console.log("hermes ok:", r.stdout.trim());
