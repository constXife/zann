import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const docsRoot = path.join(repoRoot, "docs");
const contentDocs = path.join(repoRoot, "docs", "starlight", "src", "content", "docs");

await fs.mkdir(contentDocs, { recursive: true });

const entries = await fs.readdir(contentDocs);
await Promise.all(
  entries
    .filter((entry) => entry.endsWith(".md"))
    .map((entry) => fs.unlink(path.join(contentDocs, entry)))
);

const docsEntries = await fs.readdir(docsRoot);
await Promise.all(
  docsEntries
    .filter((entry) => entry.endsWith(".md"))
    .map((entry) =>
      fs.copyFile(path.join(docsRoot, entry), path.join(contentDocs, entry))
    )
);
