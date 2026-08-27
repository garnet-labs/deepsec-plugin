import * as fs from "node:fs/promises";
import * as path from "node:path";
import { correlateFindingToRuntime, type CorrelateOptions } from "../correlate.js";
import { GarnetClient } from "../garnet-client.js";
import type { RuntimeObservationStatus } from "../types/garnet.js";

interface FluentCommand {
  description(description: string): FluentCommand;
  requiredOption(flag: string, description: string): FluentCommand;
  option(flag: string, description: string, defaultValue?: string): FluentCommand;
  action(fn: (options: Record<string, string>) => Promise<void> | void): FluentCommand;
}

export interface CommanderProgram {
  command(name: string): FluentCommand;
}

interface ExportedFinding {
  metadata: {
    filePath: string;
    lineNumbers?: number[];
  };
  [key: string]: unknown;
}

export interface CorrelationSummary extends Record<RuntimeObservationStatus, number> {
  total: number;
}

export async function correlateExportedFindings(
  client: GarnetClient,
  findings: ExportedFinding[],
  options: CorrelateOptions,
) {
  const summary: CorrelationSummary = {
    total: findings.length,
    "behavior-observed": 0,
    "path-observed": 0,
    "not-observed": 0,
    "unable-to-verify": 0,
  };
  const correlated = [];

  for (const finding of findings) {
    if (!finding.metadata?.filePath) {
      throw new Error("deepsec finding is missing metadata.filePath");
    }
    const garnet = await correlateFindingToRuntime(
      client,
      {
        filePath: finding.metadata.filePath,
        lineNumbers: finding.metadata.lineNumbers,
      },
      options,
    );
    summary[garnet.status]++;
    correlated.push({ ...finding, garnet });
  }
  return { findings: correlated, summary };
}

export function registerCorrelateCommand(
  program: CommanderProgram,
  opts: { apiToken: string; baseUrl?: string },
): void {
  program
    .command("garnet-correlate")
    .description("Add Garnet runtime observations to a Deepsec JSON export")
    .requiredOption(
      "--findings <file>",
      "JSON file produced by deepsec export --format json --out <file>",
    )
    .requiredOption("--repository <repo>", "GitHub repository in owner/repo form")
    .option("--workflow <name>", "Query a specific workflow name")
    .option("--out <file>", "Correlated JSON output", "./.deepsec/garnet-correlated.json")
    .option("--summary <file>", "Summary JSON output")
    .action(async (options) => {
      const input = JSON.parse(await fs.readFile(options.findings!, "utf8")) as unknown;
      if (!Array.isArray(input)) {
        throw new Error("Deepsec JSON export must be an array of findings");
      }

      const client = new GarnetClient({ apiToken: opts.apiToken, baseUrl: opts.baseUrl });
      const result = await correlateExportedFindings(client, input as ExportedFinding[], {
        repository: options.repository!,
        workflowName: options.workflow,
      });
      const outFile = options.out!;
      const summaryFile =
        options.summary ??
        (outFile.endsWith(".json")
          ? outFile.replace(/\.json$/, ".summary.json")
          : `${outFile}.summary.json`);

      await fs.mkdir(path.dirname(path.resolve(outFile)), { recursive: true });
      await fs.mkdir(path.dirname(path.resolve(summaryFile)), { recursive: true });
      await fs.writeFile(outFile, JSON.stringify(result.findings, null, 2) + "\n", "utf8");
      await fs.writeFile(summaryFile, JSON.stringify(result.summary, null, 2) + "\n", "utf8");
      console.log("garnet-correlate:", result.summary);
    });
}
