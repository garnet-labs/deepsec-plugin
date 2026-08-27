import { describe, it, expect } from "vitest";
import { GarnetClient } from "../garnet-client.js";
import { garnetGithubPrNotifier } from "../notifiers/github-pr.js";

function fakeGarnetFetch(routes: Record<string, unknown>): typeof fetch {
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

describe("garnetGithubPrNotifier", () => {
  it("posts a PR comment that includes Garnet runtime evidence", async () => {
    const garnet = new GarnetClient({
      apiToken: "t",
      fetchImpl: fakeGarnetFetch({
        "/v1/runs?repository=garnet-labs%2Fdub&limit=5": [
          { runId: "r1", workflowName: "Playwright E2E Tests", startedAt: "2026-05-04T22:52:26Z" },
        ],
        "/v1/runs/r1/events?path=apps%2Fweb%2Flib%2Fauth.ts": [
          { kind: "process.spawn", ts: "x", pid: 1, ppid: 0, comm: "node", path: "apps/web/lib/auth.ts" },
        ],
        "/v1/runs/r1/flows?path=apps%2Fweb%2Flib%2Fauth.ts": [
          { flowId: "f1", pid: 1, comm: "node", destAddr: "1.2.3.4", destPort: 443, destDomain: "webhook.site", bytesOut: 512, bytesIn: 64, startedAt: "x", policyDecision: "allow" },
        ],
        "/v1/runs/r1/detections?path=apps%2Fweb%2Flib%2Fauth.ts": [
          { recipeSlug: "secret_exfiltration", severity: "high", ts: "x", pid: 1, comm: "node", details: "Outbound exfiltration pattern", evidenceEventIds: ["e1"] },
        ],
      }),
    });

    let postedBody = "";
    const notifier = garnetGithubPrNotifier({
      garnet,
      repository: "garnet-labs/dub",
      github: {
        token: "ghs_test",
        owner: "garnet-labs",
        repo: "dub",
        pullNumber: 123,
        fetchImpl: (async (_input: RequestInfo | URL, init?: RequestInit) => {
          postedBody = String(init?.body ?? "");
          return new Response(
            JSON.stringify({ id: 987, html_url: "https://github.com/garnet-labs/dub/pull/123#issuecomment-987" }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }) as typeof fetch,
      },
    });

    const out = await notifier.notify({
      finding: {
        severity: "high",
        title: "Potential token leak",
        description: "Untrusted path can trigger outbound request with sensitive material.",
        recommendation: "Validate destination and block untrusted egress.",
        lineNumbers: [12, 15],
        vulnSlug: "token-leak",
        confidence: "high",
      },
      fileRecord: { filePath: "apps/web/lib/auth.ts", projectId: "dub" },
      projectId: "dub",
    });

    const body = JSON.parse(postedBody) as { body: string };
    expect(body.body).toContain("#### Garnet runtime correlation");
    expect(body.body).toContain("Runtime evidence: exploitable");
    expect(body.body).toContain("secret_exfiltration");
    expect(body.body).toContain("webhook.site");
    expect(out).toEqual({
      externalId: "987",
      externalUrl: "https://github.com/garnet-labs/dub/pull/123#issuecomment-987",
    });
  });
});
