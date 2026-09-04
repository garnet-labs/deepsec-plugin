import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { registerCorrelateCommand } from "../commands/correlate-cmd.js";

interface CapturedCommand {
  action?: (options: Record<string, string>) => Promise<void> | void;
}

function captureProgram() {
  const captured: CapturedCommand = {};
  const command = {
    description: () => command,
    requiredOption: () => command,
    option: () => command,
    action: (fn: CapturedCommand["action"]) => {
      captured.action = fn;
      return command;
    },
  };
  return { program: { command: () => command }, captured };
}

describe("registerCorrelateCommand", () => {
  it("processes the JSON array emitted by current Deepsec", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "garnet-deepsec-"));
    const inputFile = path.join(root, "deepsec-findings.json");
    const outputFile = path.join(root, "correlated.json");
    const summaryFile = path.join(root, "summary.json");
    const commentFile = path.join(root, "comment.md");
    await fs.writeFile(
      inputFile,
      JSON.stringify([
        {
          title: "Review outbound destination",
          metadata: {
            filePath: "demo/runtime-demo.mjs",
            lineNumbers: [1],
          },
        },
      ]),
    );

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const key = url.pathname + url.search;
      const routes: Record<string, unknown> = {
        "/v1/runs?repository=garnet-labs%2Fdeepsec-plugin&limit=5": [
          { runId: "123", workflowName: "CI", startedAt: "2026-08-27T00:00:00Z" },
        ],
        "/v1/runs/123/events?path=demo%2Fruntime-demo.mjs": [
          {
            kind: "process.spawn",
            ts: "x",
            pid: 1,
            ppid: 0,
            comm: "node",
            path: "demo/runtime-demo.mjs",
          },
        ],
        "/v1/runs/123/flows?path=demo%2Fruntime-demo.mjs": [],
        "/v1/runs/123/detections?path=demo%2Fruntime-demo.mjs": [],
      };
      const body = routes[key];
      return body === undefined ? new Response("not found", { status: 404 }) : Response.json(body);
    }) as typeof fetch;

    try {
      const { program, captured } = captureProgram();
      registerCorrelateCommand(program, { apiToken: "test" });
      await captured.action!({
        findings: inputFile,
        repository: "garnet-labs/deepsec-plugin",
        runId: "",
        out: outputFile,
        summary: summaryFile,
        commentOut: commentFile,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    const output = JSON.parse(await fs.readFile(outputFile, "utf8"));
    const summary = JSON.parse(await fs.readFile(summaryFile, "utf8"));
    const comment = await fs.readFile(commentFile, "utf8");
    expect(output[0].metadata.filePath).toBe("demo/runtime-demo.mjs");
    expect(output[0].garnet.status).toBe("path-observed");
    expect(comment).toContain("Runtime evidence for DeepSec findings");
    expect(comment).toContain("Review outbound destination");
    expect(summary).toEqual({
      total: 1,
      "behavior-observed": 0,
      "path-observed": 1,
      "not-observed": 0,
      "unable-to-verify": 0,
    });
  });
});
