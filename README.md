# `@garnet-org/deepsec-plugin`

Experimental integration between [Vercel Deepsec](https://github.com/vercel-labs/deepsec)
and Garnet Runtime Review. Deepsec supplies a static finding; Garnet supplies a
separate, factual record of what an instrumented CI job executed and reached.

The integration does not turn runtime observations into “safe,” “malicious,” or
“exploitable” verdicts. Repository policy and reviewers retain the merge decision.

## What works today

- The package compiles against the public Deepsec `2.x` plugin interfaces.
- `deepsec garnet-correlate` reads the JSON array produced by
  `deepsec export --format json`; its path-scoped Garnet API adapter is
  experimental and must be validated against the target deployment before release.
- Correlation output distinguishes `behavior-observed`, `path-observed`,
  `not-observed`, and `unable-to-verify`.
- Failed or incomplete evidence queries cannot become an absence claim.
- CI runs the SHA-pinned Garnet Action, which publishes the visible Runtime Review
  receipt for each pull request.

Deepsec currently registers notifier plugins but does not invoke them in its command
path. The typed GitHub notifier adapter and its contract test are retained for that
future hook; it is not presented as the live demo surface.

## Install

```bash
npm install --save-dev deepsec @garnet-org/deepsec-plugin
```

## Configure

```ts
import { defineConfig } from "deepsec/config";
import garnetPlugin from "@garnet-org/deepsec-plugin";

export default defineConfig({
  projects: [{ id: "my-repo", root: ".." }],
  plugins: [
    garnetPlugin({
      workflowName: "CI",
    }),
  ],
});
```

The plugin reads `GARNET_API_TOKEN` and `GITHUB_REPOSITORY` from the environment by
default. Do not expose the Garnet token to untrusted fork pull requests.

## Correlate a Deepsec export

```bash
npx deepsec export --format json --out .deepsec/findings.json

npx deepsec garnet-correlate \
  --findings .deepsec/findings.json \
  --repository "$GITHUB_REPOSITORY" \
  --run-id "$GITHUB_RUN_ID" \
  --workflow "CI" \
  --comment-out .deepsec/garnet-comment.md \
  --out .deepsec/garnet-correlated.json
```

The command writes the enriched finding array and a sibling
`.summary.json` file. Runtime data remains supporting evidence rather than a
replacement for Deepsec revalidation or repository policy.

In CI, pass `--run-id "$GITHUB_RUN_ID"` (or rely on the environment variable)
to bind every observation to the exact workflow run that exercised the code.
The recent-run lookup remains available for local exploration, but should not
be used as merge evidence.

## Live pull request proof

This repository's CI starts Garnet before install, build, tests, and a dedicated
runtime demo process. `demo/runtime-demo.mjs` reaches `example.com` on `main`.

For a test pull request, change only that destination to `example.org`. The expected
proof is not a mocked plugin comment. It is the Garnet-owned Check/comment and exact
Execution Profile showing the destination delta for the PR head:

```text
main:     node -> example.com
test PR:  node -> example.org
```

Reviewers can then compare Deepsec's static description of the changed script with
Garnet's observed execution receipt. Neither system silently decides whether to
merge.

## Observation contract

| Status | Meaning |
|---|---|
| `behavior-observed` | A detection or denied egress was returned for the queried path |
| `path-observed` | File-attributed runtime events were returned |
| `not-observed` | No file-attributed event was returned from complete queries; this is not proof of unreachability |
| `unable-to-verify` | No profile was available, or incomplete queries prevent an absence claim |

## License

Apache-2.0.
