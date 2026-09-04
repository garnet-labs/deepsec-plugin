import { describe, expect, it } from "vitest";
import { correlateFindingToRuntime } from "../correlate.js";
import { GarnetClient } from "../garnet-client.js";

function fakeFetch(routes: Record<string, unknown>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const key = url.pathname + url.search;
    const body = routes[key];
    if (body instanceof Error) throw body;
    if (body === undefined) return new Response("not found", { status: 404 });
    return Response.json(body);
  }) as typeof fetch;
}

describe("correlateFindingToRuntime", () => {
  it("fails closed when no profiles exist", async () => {
    const client = new GarnetClient({
      apiToken: "test",
      fetchImpl: fakeFetch({
        "/v1/runs?repository=garnet-labs%2Fdeepsec-plugin&limit=5": [],
      }),
    });
    const result = await correlateFindingToRuntime(
      client,
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin" },
    );
    expect(result.status).toBe("unable-to-verify");
    expect(result.captureStatus).toBe("none");
  });

  it("does not turn absence into an unreachable or clean claim", async () => {
    const routes = profileRoutes({ events: [], flows: [], detections: [] });
    const result = await correlateFindingToRuntime(
      new GarnetClient({ apiToken: "test", fetchImpl: fakeFetch(routes) }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin" },
    );
    expect(result.status).toBe("not-observed");
    expect(result.reasoning).toContain("does not prove");
  });

  it("reports observations without claiming exploitability", async () => {
    const routes = profileRoutes({
      events: [
        {
          kind: "process.spawn",
          ts: "2026-08-27T00:00:00Z",
          pid: 12,
          ppid: 1,
          comm: "node",
          path: "demo/runtime-demo.mjs",
        },
      ],
      flows: [
        {
          flowId: "flow-1",
          pid: 12,
          comm: "node",
          destAddr: "93.184.216.34",
          destPort: 443,
          destDomain: "example.com",
          bytesOut: 120,
          bytesIn: 500,
          startedAt: "2026-08-27T00:00:00Z",
          policyDecision: "deny",
        },
      ],
      detections: [],
    });
    const result = await correlateFindingToRuntime(
      new GarnetClient({ apiToken: "test", fetchImpl: fakeFetch(routes) }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin" },
    );
    expect(result.status).toBe("behavior-observed");
    expect(result.reasoning).toContain("not an exploitability verdict");
    expect(result.networkDestinations[0]?.domain).toBe("example.com");
  });

  it("returns unable-to-verify when an absence result has partial capture", async () => {
    const routes = profileRoutes({
      events: new Error("events unavailable"),
      flows: [],
      detections: [],
    });
    const result = await correlateFindingToRuntime(
      new GarnetClient({ apiToken: "test", fetchImpl: fakeFetch(routes) }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin" },
    );
    expect(result.status).toBe("unable-to-verify");
    expect(result.captureStatus).toBe("partial");
    expect(result.limitations).toHaveLength(1);
  });

  it("binds correlation to an explicitly requested run", async () => {
    const routes = {
      "/api/v1/profiles/456": {
        id: "profile-456",
        agentID: "agent-456",
        job: "DeepSec runtime evidence",
        runID: "456",
        createdAt: "2026-09-04T00:00:00Z",
        data: {
          network: {
            egress: {
              peers: [
                {
                  remote_address: "93.184.216.34",
                  remote_names: ["example.com"],
                  remote_ports: ["443"],
                  result: "pass",
                  proc_trees: [
                    {
                      pid: 12,
                      process: "node",
                      arguments: "node demo/runtime-demo.mjs",
                    },
                  ],
                },
              ],
            },
          },
        },
      },
    };
    const result = await correlateFindingToRuntime(
      new GarnetClient({ apiToken: "test", fetchImpl: fakeFetch(routes) }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin", runId: "456" },
    );
    expect(result.status).toBe("path-observed");
    expect(result.networkDestinations[0]?.domain).toBe("example.com");
    expect(result.correlatedRuns).toEqual([
      {
        runId: "456",
        workflowName: "DeepSec runtime evidence",
        startedAt: "2026-09-04T00:00:00Z",
      },
    ]);
  });
});

function profileRoutes(input: {
  events: unknown;
  flows: unknown;
  detections: unknown;
}) {
  return {
    "/v1/runs?repository=garnet-labs%2Fdeepsec-plugin&limit=5": [
      {
        runId: "123",
        workflowName: "CI",
        startedAt: "2026-08-27T00:00:00Z",
      },
    ],
    "/v1/runs/123/events?path=demo%2Fruntime-demo.mjs": input.events,
    "/v1/runs/123/flows?path=demo%2Fruntime-demo.mjs": input.flows,
    "/v1/runs/123/detections?path=demo%2Fruntime-demo.mjs": input.detections,
  };
}
