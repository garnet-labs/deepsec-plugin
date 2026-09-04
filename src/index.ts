import type { DeepsecPlugin } from "deepsec/config";
import { registerCorrelateCommand } from "./commands/correlate-cmd.js";
import { GarnetClient } from "./garnet-client.js";
import { garnetGithubPrNotifier } from "./notifiers/github-pr.js";

export interface GarnetPluginOptions {
  apiToken?: string;
  baseUrl?: string;
  repository?: string;
  workflowName?: string;
  github?: {
    token?: string;
    pullNumber?: number;
  };
}

export default function garnetPlugin(opts: GarnetPluginOptions = {}): DeepsecPlugin {
  const apiToken = opts.apiToken ?? process.env.GARNET_API_TOKEN;
  const repository = opts.repository ?? process.env.GITHUB_REPOSITORY;
  const plugin: DeepsecPlugin = { name: "@garnet-org/deepsec-plugin" };

  if (!apiToken) return plugin;

  const client = new GarnetClient({ apiToken, baseUrl: opts.baseUrl });
  plugin.commands = (program) =>
    registerCorrelateCommand(program as Parameters<typeof registerCorrelateCommand>[0], {
      apiToken,
      baseUrl: opts.baseUrl,
    });

  const githubToken = opts.github?.token ?? process.env.GITHUB_TOKEN;
  const pullNumber = opts.github?.pullNumber ?? parsePrNumberFromRef(process.env.GITHUB_REF);
  const runId = process.env.GITHUB_RUN_ID;
  const [owner, repo, ...extra] = repository?.split("/") ?? [];
  if (
    githubToken &&
    runId &&
    pullNumber !== null &&
    owner &&
    repo &&
    extra.length === 0
  ) {
    plugin.notifiers = [
      garnetGithubPrNotifier({
        garnet: client,
        repository: `${owner}/${repo}`,
        runId,
        github: { token: githubToken, owner, repo, pullNumber },
      }),
    ];
  }
  return plugin;
}

function parsePrNumberFromRef(ref: string | undefined): number | null {
  const match = ref?.match(/^refs\/pull\/(\d+)\//);
  return match ? Number(match[1]) : null;
}

export { correlateExportedFindings } from "./commands/correlate-cmd.js";
export { correlateFindingToRuntime } from "./correlate.js";
export { GarnetClient } from "./garnet-client.js";
export type {
  GarnetProfile,
  RuntimeCorrelation,
  RuntimeObservationStatus,
} from "./types/garnet.js";
