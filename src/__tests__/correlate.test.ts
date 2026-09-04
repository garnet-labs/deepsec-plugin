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
        "/api/v1/agents/agent-456/profiles?run_id=123&first=20": {
          items: [],
          pageInfo: { totalCount: 0, hasNextPage: false, hasPreviousPage: false },
        },
      }),
    });
    const result = await correlateFindingToRuntime(
      client,
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin", runId: "123", agentId: "agent-456" },
    );
    expect(result.status).toBe("unable-to-verify");
    expect(result.captureStatus).toBe("none");
  });

  it("does not turn absence into an unreachable or clean claim", async () => {
    const routes = profileRoutes({ events: [], flows: [], detections: [] });
    const result = await correlateFindingToRuntime(
      new GarnetClient({ apiToken: "test", fetchImpl: fakeFetch(routes) }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin", runId: "123" },
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
      { repository: "garnet-labs/deepsec-plugin", runId: "123" },
    );
    expect(result.status).toBe("behavior-observed");
    expect(result.reasoning).toContain("not an exploitability verdict");
    expect(result.networkDestinations[0]?.domain).toBe("example.com");
  });

  it("returns unable-to-verify when the exact profile is unavailable", async () => {
    const result = await correlateFindingToRuntime(
      new GarnetClient({
        apiToken: "test",
        fetchImpl: fakeFetch({}),
      }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin", runId: "404" },
    );

    expect(result.status).toBe("unable-to-verify");
    expect(result.captureStatus).toBe("none");
    expect(result.limitations[0]).toContain("Garnet profile for run 404 unavailable");
  });

  it("returns unable-to-verify when the exact profile belongs to another run or repository", async () => {
    const result = await correlateFindingToRuntime(
      new GarnetClient({
        apiToken: "test",
        fetchImpl: fakeFetch({
          "/api/v1/profiles/456": {
            id: "profile-456",
            agentID: "agent-456",
            githubOrg: "other-org",
            repo: "other-repo",
            runAttempt: 1,
            github_details_verified: true,
            job: "DeepSec runtime evidence",
            runID: "wrong-run",
            createdAt: "2026-09-04T00:00:00Z",
          },
        }),
      }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin", runId: "456" },
    );

    expect(result.status).toBe("unable-to-verify");
    expect(result.limitations).toEqual([
      "Garnet profile profile-456 belongs to other-org/other-repo run wrong-run, expected garnet-labs/deepsec-plugin run 456",
    ]);
  });

  it("accepts profile identity fields emitted by the control-plane API", async () => {
    const result = await correlateFindingToRuntime(
      new GarnetClient({
        apiToken: "test",
        fetchImpl: fakeFetch({
          "/api/v1/profiles/456": {
            id: "profile-456",
            agentID: "agent-456",
            githubOrg: "garnet-labs",
            repo: "deepsec-plugin",
            runAttempt: 1,
            github_details_verified: true,
            job: "DeepSec runtime evidence",
            runID: "456",
            createdAt: "2026-09-04T00:00:00Z",
          },
        }),
      }),
      { filePath: "demo/runtime-demo.mjs" },
      { repository: "garnet-labs/deepsec-plugin", runId: "456" },
    );

    expect(result.status).toBe("not-observed");
    expect(result.limitations).toEqual([]);
  });

  it("binds correlation to an explicitly requested run", async () => {
    const routes = {
      "/api/v1/profiles/456": {
        id: "profile-456",
        agentID: "agent-456",
        githubOrg: "garnet-labs",
        repo: "deepsec-plugin",
        runAttempt: 1,
        github_details_verified: true,
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
                      executable: "/opt/hostedtoolcache/node/22.19.0/x64/bin/node",
                      github_step: "8. Exercise the reviewed path",
                      ancestry: [
                        "systemd",
                        "hosted-compute-",
                        "Runner.Listener",
                        "Runner.Worker",
                        "bash",
                        "node",
                      ],
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
      {
        repository: "garnet-labs/deepsec-plugin",
        runId: "456",
        stepName: "Exercise the reviewed path",
      },
    );
    expect(result.status).toBe("path-observed");
    expect(result.networkDestinations[0]?.domain).toBe("example.com");
    expect(result.networkDestinations[0]?.executionChain).toBe(
      "bash → node → example.com:443",
    );
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
  const events = input.events instanceof Error
    ? []
    : (input.events as Array<Record<string, unknown>>);
  const flows = input.flows instanceof Error
    ? []
    : (input.flows as Array<Record<string, unknown>>);
  return {
    "/api/v1/profiles/123": {
      id: "profile-123",
      agentID: "agent-123",
      githubOrg: "garnet-labs",
      repo: "deepsec-plugin",
      runAttempt: 1,
      github_details_verified: true,
      job: "CI",
      runID: "123",
      createdAt: "2026-08-27T00:00:00Z",
      data: {
        network: {
          egress: {
            peers: [
              {
                remote_address: String(flows[0]?.destAddr ?? "93.184.216.34"),
                remote_names: flows[0]?.destDomain ? [String(flows[0].destDomain)] : [],
                remote_ports: flows[0]?.destPort ? [String(flows[0].destPort)] : [],
                result: flows[0]?.policyDecision === "deny" ? "fail" : "pass",
                proc_trees: events.map((event) => ({
                  pid: event.pid,
                  process: event.comm,
                  arguments: `${event.comm} demo/runtime-demo.mjs`,
                  github_step: "Exercise the reviewed path",
                })),
              },
            ],
          },
        },
      },
    },
  };
}
