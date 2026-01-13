import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const srcDir = path.join(repoRoot, "docs", "screenshots");
const destDir = path.join(repoRoot, "docs", "starlight", "public", "screenshots");

await fs.mkdir(destDir, { recursive: true });

const entries = await fs.readdir(destDir);
await Promise.all(
  entries
    .filter((entry) => entry.endsWith(".png") || entry.endsWith(".jpg") || entry.endsWith(".jpeg"))
    .map((entry) => fs.unlink(path.join(destDir, entry)))
);

const srcEntries = await fs.readdir(srcDir);
await Promise.all(
  srcEntries
    .filter((entry) => entry.endsWith(".png") || entry.endsWith(".jpg") || entry.endsWith(".jpeg"))
    .map((entry) =>
      fs.copyFile(path.join(srcDir, entry), path.join(destDir, entry))
    )
);
