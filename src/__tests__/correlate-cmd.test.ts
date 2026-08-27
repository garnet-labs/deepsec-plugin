import { describe, it, expect } from "vitest";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { registerCorrelateCommand } from "../commands/correlate-cmd.js";

interface CapturedCommand {
  action?: (opts: Record<string, string>) => Promise<void> | void;
}

function makeProgramCapture() {
  const captured: CapturedCommand = {};
  const fluent = {
    description: () => fluent,
    requiredOption: () => fluent,
    option: () => fluent,
    action: (fn: (opts: Record<string, string>) => Promise<void> | void) => {
      captured.action = fn;
      return fluent;
    },
  };

  const program = {
    command: () => fluent,
  };
  return { program, captured };
}

function fakeGarnetFetch(routes: Record<string, unknown>, seenPaths: string[]): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const p = new URL(url).pathname + new URL(url).search;
    seenPaths.push(p);
    const body = routes[p];
    if (body === undefined) {
      return new Response("not found", { status: 404 });
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

describe("registerCorrelateCommand", () => {
  it("enriches exported findings and writes summary with Garnet evidence", async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "garnet-correlate-test-"));
    const inDir = path.join(tempRoot, "findings");
    const outDir = path.join(tempRoot, "correlated");
    await fs.mkdir(inDir, { recursive: true });
    await fs.writeFile(
      path.join(inDir, "finding-1.json"),
      JSON.stringify({ filePath: "apps/web/lib/auth.ts", lineNumbers: [12], findingId: "f-1" }),
      "utf8",
    );

    const seenGarnetPaths: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fakeGarnetFetch({
      "/v1/runs?repository=garnet-labs%2Fdub&limit=5": [
        { runId: "r1", workflowName: "Playwright E2E Tests", startedAt: "2026-05-04T22:52:26Z" },
      ],
      "/v1/runs/r1/events?path=apps%2Fweb%2Flib%2Fauth.ts": [
        { kind: "process.spawn", ts: "x", pid: 1, ppid: 0, comm: "node", path: "apps/web/lib/auth.ts" },
      ],
      "/v1/runs/r1/flows?path=apps%2Fweb%2Flib%2Fauth.ts": [
        { flowId: "f1", pid: 1, comm: "node", destAddr: "1.2.3.4", destPort: 443, destDomain: "webhook.site", bytesOut: 99, bytesIn: 1, startedAt: "x", policyDecision: "deny" },
      ],
      "/v1/runs/r1/detections?path=apps%2Fweb%2Flib%2Fauth.ts": [],
    }, seenGarnetPaths);

    try {
      const { program, captured } = makeProgramCapture();
      registerCorrelateCommand(program, { apiToken: "t" });
      expect(captured.action).toBeTypeOf("function");

      await captured.action!({
        "findings-dir": inDir,
        repository: "garnet-labs/dub",
        out: outDir,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    const outRaw = await fs.readFile(path.join(outDir, "finding-1.json"), "utf8");
    const outJson = JSON.parse(outRaw) as { garnet: { verdict: string; networkDestinations: Array<{ domain?: string }> } };
    expect(outJson.garnet.verdict).toBe("exploitable-runtime-confirmed");
    expect(outJson.garnet.networkDestinations[0]?.domain).toBe("webhook.site");

    const summaryRaw = await fs.readFile(path.join(outDir, "_summary.json"), "utf8");
    const summary = JSON.parse(summaryRaw) as Record<string, number>;
    expect(summary).toEqual({
      total: 1,
      confirmed: 1,
      reachable: 0,
      unreachable: 0,
      missing: 0,
    });

    expect(seenGarnetPaths).toEqual([
      "/v1/runs?repository=garnet-labs%2Fdub&limit=5",
      "/v1/runs/r1/events?path=apps%2Fweb%2Flib%2Fauth.ts",
      "/v1/runs/r1/flows?path=apps%2Fweb%2Flib%2Fauth.ts",
      "/v1/runs/r1/detections?path=apps%2Fweb%2Flib%2Fauth.ts",
    ]);
  });
});
