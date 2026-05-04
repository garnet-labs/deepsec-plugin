import { describe, it, expect } from "vitest";
import { correlateFindingToRuntime } from "../correlate.js";
import { GarnetClient } from "../garnet-client.js";

// Build a fake fetch that serves canned Garnet API responses.
function fakeFetch(routes: Record<string, unknown>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const path = new URL(url).pathname + new URL(url).search;
    const body = routes[path];
    if (body === undefined) {
      return new Response("not found", { status: 404 });
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

describe("correlateFindingToRuntime", () => {
  it("returns no-runtime-data when no runs exist", async () => {
    const client = new GarnetClient({
      apiToken: "t",
      fetchImpl: fakeFetch({
        "/v1/runs?repository=garnet-labs%2Fdub&limit=5": [],
      }),
    });
    const c = await correlateFindingToRuntime(
      client,
      { filePath: "apps/web/lib/auth.ts" },
      { repository: "garnet-labs/dub" },
    );
    expect(c.verdict).toBe("no-runtime-data");
  });

  it("returns unreachable when path has zero events", async () => {
    const client = new GarnetClient({
      apiToken: "t",
      fetchImpl: fakeFetch({
        "/v1/runs?repository=garnet-labs%2Fdub&limit=5": [
          { runId: "r1", workflowName: "Playwright E2E Tests", startedAt: "2026-05-04T22:52:26Z" },
        ],
        "/v1/runs/r1/events?path=apps%2Fweb%2Flib%2Fauth.ts": [],
        "/v1/runs/r1/flows?path=apps%2Fweb%2Flib%2Fauth.ts": [],
        "/v1/runs/r1/detections?path=apps%2Fweb%2Flib%2Fauth.ts": [],
      }),
    });
    const c = await correlateFindingToRuntime(
      client,
      { filePath: "apps/web/lib/auth.ts" },
      { repository: "garnet-labs/dub" },
    );
    expect(c.verdict).toBe("unreachable-in-this-suite");
    expect(c.pathExecuted).toBe(false);
  });

  it("returns reachable-but-no-abuse when events exist but no detections/denials", async () => {
    const client = new GarnetClient({
      apiToken: "t",
      fetchImpl: fakeFetch({
        "/v1/runs?repository=garnet-labs%2Fdub&limit=5": [
          { runId: "r1", workflowName: "Playwright E2E Tests", startedAt: "2026-05-04T22:52:26Z" },
        ],
        "/v1/runs/r1/events?path=apps%2Fweb%2Flib%2Fauth.ts": [
          { kind: "process.spawn", ts: "x", pid: 1, ppid: 0, comm: "node", path: "apps/web/lib/auth.ts" },
        ],
        "/v1/runs/r1/flows?path=apps%2Fweb%2Flib%2Fauth.ts": [
          { flowId: "f1", pid: 1, comm: "node", destAddr: "1.2.3.4", destPort: 443, destDomain: "registry.npmjs.org", bytesOut: 100, bytesIn: 200, startedAt: "x", policyDecision: "allow" },
        ],
        "/v1/runs/r1/detections?path=apps%2Fweb%2Flib%2Fauth.ts": [],
      }),
    });
    const c = await correlateFindingToRuntime(
      client,
      { filePath: "apps/web/lib/auth.ts" },
      { repository: "garnet-labs/dub" },
    );
    expect(c.verdict).toBe("reachable-but-no-abuse");
    expect(c.pathExecuted).toBe(true);
  });

  it("returns exploitable-runtime-confirmed when the network policy denied an egress from the path", async () => {
    const client = new GarnetClient({
      apiToken: "t",
      fetchImpl: fakeFetch({
        "/v1/runs?repository=garnet-labs%2Fdub&limit=5": [
          { runId: "r1", workflowName: "Garnet x DeepSec — Supply-Chain Blindspot Demo", startedAt: "2026-05-04T23:01:18Z" },
        ],
        "/v1/runs/r1/events?path=.garnet-demo%2Fpostinstall.js": [
          { kind: "process.spawn", ts: "x", pid: 1234, ppid: 1, comm: "node", path: ".garnet-demo/postinstall.js" },
        ],
        "/v1/runs/r1/flows?path=.garnet-demo%2Fpostinstall.js": [
          { flowId: "f1", pid: 1234, comm: "node", destAddr: "46.4.105.116", destPort: 443, destDomain: "webhook.site", bytesOut: 0, bytesIn: 0, startedAt: "x", policyDecision: "deny" },
        ],
        "/v1/runs/r1/detections?path=.garnet-demo%2Fpostinstall.js": [],
      }),
    });
    const c = await correlateFindingToRuntime(
      client,
      { filePath: ".garnet-demo/postinstall.js" },
      { repository: "garnet-labs/dub" },
    );
    expect(c.verdict).toBe("exploitable-runtime-confirmed");
    expect(c.reasoning).toMatch(/denied/);
    expect(c.networkDestinations[0]?.domain).toBe("webhook.site");
  });
});
