// A deepsec NotifierPlugin that posts a single PR comment per finding,
// enriched with Garnet runtime correlation.
//
// Wires into the standard deepsec notifier slot. When deepsec produces a
// finding, this notifier:
//   1. Calls correlateFindingToRuntime() against the same repo/workflow.
//   2. Posts a markdown comment on the PR containing the finding + the
//      runtime correlation block.
//   3. Returns FindingNotification { externalId: <comment-id>, externalUrl }
//      so deepsec can reconcile on subsequent runs.
//
// This file is intentionally framework-agnostic about the deepsec types —
// the import path is `deepsec/config` once installed inside the deepsec
// monorepo.

import type { GarnetClient } from "../garnet-client.js";
import { correlateFindingToRuntime } from "../correlate.js";
import { renderRuntimeBlock } from "./render.js";

// Minimal duck-typed shapes mirroring deepsec/config exports. Replaced by
// the real imports when this plugin is published next to deepsec.
export interface NotifyParams {
  finding: {
    severity: string;
    title: string;
    description: string;
    recommendation: string;
    lineNumbers: number[];
    vulnSlug: string;
    confidence: "high" | "medium" | "low";
  };
  fileRecord: {
    filePath: string;
    projectId: string;
  };
  projectId: string;
}
export interface FindingNotification {
  externalId: string;
  externalUrl: string;
}
export interface NotifierPlugin {
  name: string;
  notify(p: NotifyParams): Promise<FindingNotification>;
}

export interface GarnetNotifierOptions {
  garnet: GarnetClient;
  repository: string;            // "garnet-labs/dub"
  workflowName?: string;
  // GitHub Actions context — when running inside `pnpm deepsec process` triggered by a PR.
  github: {
    token: string;               // GITHUB_TOKEN
    owner: string;
    repo: string;
    pullNumber: number;
    apiBaseUrl?: string;         // default https://api.github.com
    fetchImpl?: typeof fetch;
  };
}

export function garnetGithubPrNotifier(opts: GarnetNotifierOptions): NotifierPlugin {
  const f = opts.github.fetchImpl ?? fetch;
  const apiBase = opts.github.apiBaseUrl ?? "https://api.github.com";

  return {
    name: "@garnet-org/notifier-github-pr",
    async notify({ finding, fileRecord }) {
      const correlation = await correlateFindingToRuntime(
        opts.garnet,
        { filePath: fileRecord.filePath, lineNumbers: finding.lineNumbers },
        { repository: opts.repository, workflowName: opts.workflowName },
      );

      const body = [
        `### deepsec finding · \`${finding.vulnSlug}\` · **${finding.severity}**`,
        ``,
        `**${finding.title}**`,
        ``,
        finding.description,
        ``,
        `**Suggested fix:** ${finding.recommendation}`,
        ``,
        `📍 \`${fileRecord.filePath}\` lines ${finding.lineNumbers.join(", ")} · agent confidence: ${finding.confidence}`,
        ``,
        `---`,
        ``,
        renderRuntimeBlock(correlation),
      ].join("\n");

      const url = `${apiBase}/repos/${opts.github.owner}/${opts.github.repo}/issues/${opts.github.pullNumber}/comments`;
      const res = await f(url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${opts.github.token}`,
          accept: "application/vnd.github+json",
          "content-type": "application/json",
        },
        body: JSON.stringify({ body }),
      });
      if (!res.ok) {
        throw new Error(`github comment failed: ${res.status} ${await res.text()}`);
      }
      const data = (await res.json()) as { id: number; html_url: string };
      return { externalId: String(data.id), externalUrl: data.html_url };
    },
  };
}
