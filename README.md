# `@garnet-org/deepsec-plugin`

A [Vercel deepsec](https://github.com/vercel-labs/deepsec) plugin that supplements static findings with **runtime evidence from Garnet**. Every deepsec finding becomes a triple: the static issue, the runtime trace of the path it lives on, and a verdict that combines both.

## What it does

deepsec finds vulnerabilities in your codebase using Claude Opus 4.7 and GPT 5.5. Garnet captures eBPF-level runtime evidence (syscalls, network flows, detection-recipe matches) from your CI workflows. This plugin glues them together at the deepsec plugin surface:

- **`notifiers` slot** — when deepsec posts a finding to a PR, the comment includes a Garnet runtime correlation block: did this code path actually fire in CI? what did it touch? was any egress denied by network policy?
- **`commands` slot** — adds a `deepsec garnet-correlate` subcommand that enriches `deepsec export`-produced finding JSONs with the same correlation, for offline triage.

Per-finding output looks like this:

| Verdict | When it's emitted |
|---|---|
| 🔴 `exploitable-runtime-confirmed` | Garnet captured a detection on the path's process tree, **or** the network policy denied an egress attempt from it |
| 🟡 `reachable-but-no-abuse` | Path fired under tests, no detections this run |
| ⚪ `unreachable-in-this-suite` | No runtime events for this path across recent runs (likely lower priority) |
| ⚫ `no-runtime-data` | No Garnet profile available |

## Install

```bash
pnpm add -D @garnet-org/deepsec-plugin
```

## Wire it up

```ts
// deepsec.config.ts
import { defineConfig } from "deepsec/config";
import garnetPlugin from "@garnet-org/deepsec-plugin";

export default defineConfig({
  projects: [{ id: "dub", root: ".." }],
  plugins: [
    garnetPlugin({
      // Reads from process.env by default:
      //   GARNET_API_TOKEN, GITHUB_REPOSITORY, GITHUB_TOKEN, GITHUB_REF
      workflowName: "Playwright E2E Tests",
    }),
  ],
});
```

## CI flow

```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]

jobs:
  # 1. Garnet runs alongside your normal CI workflows; profiles are
  #    captured automatically (see https://garnet.ai/docs/quickstart).

  # 2. deepsec runs on the PR, with the Garnet plugin loaded.
  deepsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - name: deepsec scan + process + correlate
        env:
          AI_GATEWAY_API_KEY: ${{ secrets.AI_GATEWAY_API_KEY }}
          GARNET_API_TOKEN:   ${{ secrets.GARNET_API_TOKEN }}
          GITHUB_TOKEN:       ${{ secrets.GITHUB_TOKEN }}
        run: |
          npx deepsec scan
          npx deepsec process
          npx deepsec triage
          npx deepsec export --format json-dir --out findings/
          # Plugin-registered subcommand:
          npx deepsec garnet-correlate \
            --findings-dir findings/ \
            --repository ${{ github.repository }} \
            --workflow "Playwright E2E Tests" \
            --out garnet-correlated/
```

## API

```ts
import { correlateFindingToRuntime, GarnetClient } from "@garnet-org/deepsec-plugin";

const client = new GarnetClient({ apiToken: process.env.GARNET_API_TOKEN! });
const correlation = await correlateFindingToRuntime(
  client,
  { filePath: "apps/web/lib/api/links/route.ts" },
  { repository: "garnet-labs/dub", workflowName: "Playwright E2E Tests" },
);
console.log(correlation.verdict, correlation.reasoning);
```

## Decision rule (deterministic, auditable)

```
if any detection on the process tree that touched filePath:
  → exploitable-runtime-confirmed
elif any flow.policyDecision === "deny" from that process tree:
  → exploitable-runtime-confirmed
elif any runtime event references filePath:
  → reachable-but-no-abuse
elif at least one Garnet run was correlated:
  → unreachable-in-this-suite
else:
  → no-runtime-data
```

The full correlation logic lives in [`src/correlate.ts`](src/correlate.ts) with unit tests in [`src/__tests__/correlate.test.ts`](src/__tests__/correlate.test.ts).

## License

Apache-2.0, matching deepsec.
