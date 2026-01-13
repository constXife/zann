import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export async function GET() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const docsRoot = path.resolve(here, "..");
  const specPath = path.join(docsRoot, "openapi.json");

  try {
    const body = await fs.readFile(specPath, "utf8");
    return new Response(body, {
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return new Response(
      JSON.stringify({ error: "openapi.json not found" }),
      {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}
