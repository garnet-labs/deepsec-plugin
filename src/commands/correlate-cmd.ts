// `deepsec garnet-correlate` — a custom CLI subcommand registered via the
// plugin's `commands` slot. Reads exported deepsec findings, enriches each
// with Garnet correlation, and writes a parallel JSON file.
//
// This is the path that fits CI cleanly: deepsec runs first (`scan` →
// `process` → `triage` → `export`), then a single `deepsec garnet-correlate`
// step adds runtime evidence, then exports the merged result.

import { GarnetClient } from "../garnet-client.js";
import { correlateFindingToRuntime } from "../correlate.js";
import * as fs from "node:fs/promises";
import * as path from "node:path";

interface FluentCommand {
  description(d: string): FluentCommand;
  requiredOption(flag: string, desc: string): FluentCommand;
  option(flag: string, desc: string, def?: string): FluentCommand;
  action(fn: (opts: Record<string, string>) => Promise<void> | void): FluentCommand;
}
interface CommanderProgram {
  command(name: string): FluentCommand;
}

export function registerCorrelateCommand(program: CommanderProgram, opts: {
  apiToken: string;
  baseUrl?: string;
}): void {
  program
    .command("garnet-correlate")
    .description("Enrich exported deepsec findings with Garnet runtime correlation")
    .requiredOption("--findings-dir <dir>", "Directory of exported finding JSONs (deepsec export --format json-dir)")
    .requiredOption("--repository <repo>", "GitHub repository in owner/repo form")
    .option("--workflow <name>", "Pin to a specific workflow name")
    .option("--out <dir>", "Output directory", "./.deepsec/garnet-correlated")
    .action(async (o: Record<string, string>) => {
      const client = new GarnetClient({ apiToken: opts.apiToken, baseUrl: opts.baseUrl });
      const inDir = o["findings-dir"]!;
      const outDir = o["out"]!;
      await fs.mkdir(outDir, { recursive: true });

      const entries = await fs.readdir(inDir);
      const jsons = entries.filter((e) => e.endsWith(".json"));
      let confirmed = 0, reachable = 0, unreachable = 0, missing = 0;

      for (const name of jsons) {
        const raw = JSON.parse(
          await fs.readFile(path.join(inDir, name), "utf8"),
        ) as { filePath: string; lineNumbers?: number[]; [k: string]: unknown };

        const correlation = await correlateFindingToRuntime(
          client,
          { filePath: raw.filePath, lineNumbers: raw.lineNumbers },
          { repository: o["repository"]!, workflowName: o["workflow"] },
        );

        switch (correlation.verdict) {
          case "exploitable-runtime-confirmed": confirmed++; break;
          case "reachable-but-no-abuse": reachable++; break;
          case "unreachable-in-this-suite": unreachable++; break;
          case "no-runtime-data": missing++; break;
        }

        const merged = { ...raw, garnet: correlation };
        await fs.writeFile(
          path.join(outDir, name),
          JSON.stringify(merged, null, 2),
          "utf8",
        );
      }

      const summary = { total: jsons.length, confirmed, reachable, unreachable, missing };
      await fs.writeFile(
        path.join(outDir, "_summary.json"),
        JSON.stringify(summary, null, 2),
      );
      // eslint-disable-next-line no-console
      console.log("garnet-correlate:", summary);
    });
}
