import type { NotifyParams } from "deepsec/config";
import { describe, expect, it } from "vitest";
import { GarnetClient } from "../garnet-client.js";
import { garnetGithubPrNotifier } from "../notifiers/github-pr.js";

describe("garnetGithubPrNotifier", () => {
  it("implements the Deepsec 2.x notifier contract and renders neutral evidence", async () => {
    const garnet = new GarnetClient({
      apiToken: "test",
      fetchImpl: (async (input: RequestInfo | URL) => {
        const url = new URL(typeof input === "string" ? input : input.toString());
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
        const body = routes[url.pathname + url.search];
        return body === undefined ? new Response("not found", { status: 404 }) : Response.json(body);
      }) as typeof fetch,
    });

    let posted = "";
    const notifier = garnetGithubPrNotifier({
      garnet,
      repository: "garnet-labs/deepsec-plugin",
      now: () => new Date("2026-08-27T00:00:00Z"),
      github: {
        token: "github-test",
        owner: "garnet-labs",
        repo: "deepsec-plugin",
        pullNumber: 2,
        fetchImpl: (async (_input: RequestInfo | URL, init?: RequestInit) => {
          posted = String(init?.body);
          return Response.json({
            id: 987,
            html_url: "https://github.com/garnet-labs/deepsec-plugin/pull/2#issuecomment-987",
          });
        }) as typeof fetch,
      },
    });

    const params: NotifyParams = {
      projectId: "deepsec-plugin",
      finding: {
        severity: "HIGH",
        vulnSlug: "review-egress",
        title: "Review outbound destination",
        description: "A changed script reaches a new destination.",
        recommendation: "Confirm that the destination is intended.",
        lineNumbers: [1],
        confidence: "high",
      },
      record: {
        filePath: "demo/runtime-demo.mjs",
        projectId: "deepsec-plugin",
        candidates: [],
        lastScannedAt: "2026-08-27T00:00:00Z",
        lastScannedRunId: "deepsec-1",
        fileHash: "abc",
        findings: [],
        analysisHistory: [],
        status: "analyzed",
      },
    };

    const result = await notifier.notify(params);
    const body = JSON.parse(posted).body as string;
    expect(body).toContain("#### Garnet runtime observation");
    expect(body).toContain("Code path observed in queried profiles");
    expect(body).not.toContain("exploitable");
    expect(result).toEqual({
      notifierName: "@garnet-org/notifier-github-pr",
      notifiedAt: "2026-08-27T00:00:00.000Z",
      externalId: "987",
      externalUrl:
        "https://github.com/garnet-labs/deepsec-plugin/pull/2#issuecomment-987",
    });
  });
});
