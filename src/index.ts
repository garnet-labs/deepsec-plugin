// Public entry. Returns a deepsec plugin that fills two slots:
//   - notifiers: posts PR comments with runtime correlation
//   - commands:  registers `deepsec garnet-correlate` subcommand
//
// Designed to be backward compatible: if GARNET_API_TOKEN is missing, the
// plugin no-ops cleanly so deepsec users can opt in by setting one env var.

import { GarnetClient } from "./garnet-client.js";
import { garnetGithubPrNotifier } from "./notifiers/github-pr.js";
import { registerCorrelateCommand } from "./commands/correlate-cmd.js";

export interface GarnetPluginOptions {
  apiToken?: string;          // default: process.env.GARNET_API_TOKEN
  baseUrl?: string;           // default: https://api.garnet.ai
  repository?: string;        // default: process.env.GITHUB_REPOSITORY
  workflowName?: string;      // optional pin

  // Notifier wiring. Provide when running inside a PR-triggered deepsec run.
  github?: {
    token?: string;           // default: process.env.GITHUB_TOKEN
    pullNumber?: number;      // default: parsed from GITHUB_REF
  };
}

// We use the same DeepsecPlugin shape from deepsec/config when published,
// duck-typed here to avoid a hard peer dep at build time.
export interface DeepsecPluginShape {
  name: string;
  notifiers?: unknown[];
  commands?: (program: unknown) => void;
}

export default function garnetPlugin(opts: GarnetPluginOptions = {}): DeepsecPluginShape {
  const apiToken = opts.apiToken ?? process.env.GARNET_API_TOKEN;
  const repository = opts.repository ?? process.env.GITHUB_REPOSITORY;

  if (!apiToken) {
    return {
      name: "@garnet-org/deepsec-plugin (disabled: missing GARNET_API_TOKEN)",
    };
  }

  const client = new GarnetClient({ apiToken, baseUrl: opts.baseUrl });

  const plugin: DeepsecPluginShape = {
    name: "@garnet-org/deepsec-plugin",
    commands: (program) => registerCorrelateCommand(program as never, { apiToken, baseUrl: opts.baseUrl }),
  };

  // Wire the notifier when we have everything we need.
  const ghToken = opts.github?.token ?? process.env.GITHUB_TOKEN;
  const pullNumber =
    opts.github?.pullNumber ?? parsePrNumberFromRef(process.env.GITHUB_REF);
  if (ghToken && repository && pullNumber !== null) {
    const [owner, repo] = repository.split("/");
    plugin.notifiers = [
      garnetGithubPrNotifier({
        garnet: client,
        repository,
        workflowName: opts.workflowName,
        github: { token: ghToken, owner: owner!, repo: repo!, pullNumber },
      }),
    ];
  }
  return plugin;
}

function parsePrNumberFromRef(ref: string | undefined): number | null {
  // GITHUB_REF for PR events: refs/pull/123/merge
  if (!ref) return null;
  const m = ref.match(/^refs\/pull\/(\d+)\//);
  return m ? Number(m[1]) : null;
}

export { GarnetClient } from "./garnet-client.js";
export { correlateFindingToRuntime } from "./correlate.js";
export type { RuntimeCorrelation, GarnetProfile } from "./types/garnet.js";
