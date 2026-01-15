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
    .map(async (entry) => {
      const srcPath = path.join(docsRoot, entry);
      const destPath = path.join(contentDocs, entry);
      if (entry !== "Server.md" && entry !== "ServerThreatModel.md") {
        await fs.copyFile(srcPath, destPath);
        return;
      }

      const [docTemplate, serverReadme, securityDoc] = await Promise.all([
        fs.readFile(srcPath, "utf8"),
        fs.readFile(path.join(repoRoot, "crates", "zann-server", "README.md"), "utf8"),
        fs.readFile(path.join(repoRoot, "crates", "zann-server", "SECURITY.md"), "utf8"),
      ]);
      const readmeLines = serverReadme.split(/\r?\n/);
      let trimmedReadme = serverReadme;
      if (readmeLines[0]?.startsWith("# ")) {
        trimmedReadme = readmeLines.slice(1).join("\n").replace(/^\s*\n/, "");
      }

      const securityLines = securityDoc.split(/\r?\n/);
      const trimmedSecurity = securityLines[0]?.startsWith("# ")
        ? securityLines.slice(1)
        : securityLines;
      const shiftedSecurity = trimmedSecurity
        .map((line) => {
          const match = line.match(/^(#{2,6})\s+(.*)$/);
          if (!match) {
            return line;
          }
          const level = Math.min(match[1].length + 1, 6);
          return `${"#".repeat(level)} ${match[2]}`;
        })
        .join("\n");

      if (entry === "ServerThreatModel.md") {
        const merged = docTemplate.replace(
          "<!-- ZANN_SERVER_SECURITY -->",
          shiftedSecurity.trim()
        );
        await fs.writeFile(destPath, merged, "utf8");
        return;
      }

      const readmeWithSecurity = trimmedReadme.replace(
        "<!-- SECURITY_MD_INCLUDE -->",
        shiftedSecurity.trim()
      );
      const merged = docTemplate.replace(
        "<!-- ZANN_SERVER_README -->",
        readmeWithSecurity.trim()
      );
      await fs.writeFile(destPath, merged, "utf8");
    })
);
