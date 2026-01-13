import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promises as fs } from "node:fs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const outputDir = path.join(repoRoot, "docs");
const outputPath = path.join(outputDir, "openapi.json");

await fs.mkdir(outputDir, { recursive: true });

const args = ["run", "-p", "zann-server", "--", "openapi", "-o", outputPath];
const child = spawn("cargo", args, { cwd: repoRoot, stdio: "inherit" });

child.on("exit", (code) => {
  process.exit(code ?? 1);
});

child.on("error", (err) => {
  console.error("Failed to run cargo:", err.message);
  process.exit(1);
});
