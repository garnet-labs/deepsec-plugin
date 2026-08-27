import type {
  FindingNotification,
  NotifierPlugin,
} from "deepsec/config";
import type { GarnetClient } from "../garnet-client.js";
import { correlateFindingToRuntime } from "../correlate.js";
import { escapeMarkdown, renderRuntimeBlock } from "./render.js";

export interface GarnetNotifierOptions {
  garnet: GarnetClient;
  repository: string;
  workflowName?: string;
  now?: () => Date;
  github: {
    token: string;
    owner: string;
    repo: string;
    pullNumber: number;
    apiBaseUrl?: string;
    fetchImpl?: typeof fetch;
  };
}

export function garnetGithubPrNotifier(opts: GarnetNotifierOptions): NotifierPlugin {
  const request = opts.github.fetchImpl ?? fetch;
  const apiBase = opts.github.apiBaseUrl ?? "https://api.github.com";

  return {
    name: "@garnet-org/notifier-github-pr",
    async notify({ finding, record }): Promise<FindingNotification> {
      const correlation = await correlateFindingToRuntime(
        opts.garnet,
        { filePath: record.filePath, lineNumbers: finding.lineNumbers },
        { repository: opts.repository, workflowName: opts.workflowName },
      );
      const safePath = record.filePath.replaceAll("`", "'").replace(/\s+/g, " ");
      const body = [
        `### deepsec finding: \`${finding.vulnSlug.replaceAll("`", "'")}\``,
        "",
        `Severity: ${escapeMarkdown(finding.severity)}`,
        "",
        `**${escapeMarkdown(finding.title)}**`,
        "",
        escapeMarkdown(finding.description),
        "",
        `**Suggested fix:** ${escapeMarkdown(finding.recommendation)}`,
        "",
        `Location: \`${safePath}\`, lines ${finding.lineNumbers.join(", ")}; ` +
          `agent confidence: ${escapeMarkdown(finding.confidence)}`,
        "",
        "---",
        "",
        renderRuntimeBlock(correlation),
      ].join("\n");

      const url =
        `${apiBase}/repos/${opts.github.owner}/${opts.github.repo}/issues/` +
        `${opts.github.pullNumber}/comments`;
      const response = await request(url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${opts.github.token}`,
          accept: "application/vnd.github+json",
          "content-type": "application/json",
        },
        body: JSON.stringify({ body }),
      });
      if (!response.ok) {
        throw new Error(`github comment failed: ${response.status} ${await response.text()}`);
      }
      const data = (await response.json()) as { id: number; html_url: string };
      return {
        notifierName: "@garnet-org/notifier-github-pr",
        notifiedAt: (opts.now?.() ?? new Date()).toISOString(),
        externalId: String(data.id),
        externalUrl: data.html_url,
      };
    },
  };
}
