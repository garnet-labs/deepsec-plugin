import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, readFile, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const deepsecCli = join(repo, "node_modules/deepsec/dist/cli.mjs");
const outputDir = join(here, "output");
const findingsFile = join(outputDir, "deepsec-findings.json");
const correlatedFile = join(outputDir, "garnet-correlated.json");
const summaryFile = join(outputDir, "garnet-summary.json");

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });

const requests = [];
const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  requests.push(`${request.method} ${url.pathname}${url.search}`);
  response.setHeader("content-type", "application/json");

  if (url.pathname === "/v1/runs") {
    response.end(
      JSON.stringify([
        {
          runId: "garnet-profile-demo",
          workflowName: "CI",
          startedAt: "2026-08-27T00:01:00.000Z",
        },
      ]),
    );
    return;
  }

  if (url.pathname === "/v1/runs/garnet-profile-demo/profile") {
    response.end(
      JSON.stringify({
        agentId: "agent-demo",
        repository: "garnet-labs/deepsec-plugin",
        workflowName: "CI",
        runId: "garnet-profile-demo",
        jobId: "job-demo",
        startedAt: "2026-08-27T00:01:00.000Z",
        endedAt: "2026-08-27T00:02:00.000Z",
        events: [],
        flows: [],
        detections: [],
      }),
    );
    return;
  }

  if (url.pathname.endsWith("/events")) {
    response.end(
      JSON.stringify([
        {
          kind: "process.spawn",
          ts: "2026-08-27T00:01:01.000Z",
          pid: 42,
          ppid: 1,
          comm: "node",
          args: ["node", "demo/runtime-demo.mjs"],
          path: "demo/runtime-demo.mjs",
        },
      ]),
    );
    return;
  }

  if (url.pathname.endsWith("/flows")) {
    response.end(
      JSON.stringify([
        {
          flowId: "flow-demo",
          pid: 42,
          comm: "node",
          destAddr: "93.184.216.34",
          destPort: 443,
          destDomain: "example.net",
          bytesOut: 128,
          bytesIn: 256,
          startedAt: "2026-08-27T00:01:02.000Z",
          policyDecision: "observe",
        },
      ]),
    );
    return;
  }

  if (url.pathname.endsWith("/detections")) {
    response.end("[]");
    return;
  }

  response.statusCode = 404;
  response.end(JSON.stringify({ error: "not found" }));
});

await new Promise((resolveReady) => server.listen(0, "127.0.0.1", resolveReady));
const address = server.address();
assert(address && typeof address === "object");
const baseUrl = `http://127.0.0.1:${address.port}`;

const env = {
  ...process.env,
  DEEPSEC_DATA_ROOT: join(here, "data"),
  GARNET_API_TOKEN: "deepsec-harness-demo-token",
  GARNET_API_URL: baseUrl,
};

try {
  const help = await deepsec(["--help"], env);
  assert.match(help, /garnet-correlate/);

  await deepsec(
    [
      "export",
      "--project-id",
      "deepsec-plugin-demo",
      "--format",
      "json",
      "--out",
      findingsFile,
    ],
    env,
  );
  const exported = JSON.parse(await readFile(findingsFile, "utf8"));
  assert.equal(exported.length, 1);
  assert.equal(exported[0].metadata.filePath, "demo/runtime-demo.mjs");

  await deepsec(
    [
      "garnet-correlate",
      "--findings",
      findingsFile,
      "--repository",
      "garnet-labs/deepsec-plugin",
      "--run-id",
      "garnet-profile-demo",
      "--workflow",
      "CI",
      "--out",
      correlatedFile,
      "--summary",
      summaryFile,
    ],
    env,
  );

  const correlated = JSON.parse(await readFile(correlatedFile, "utf8"));
  const summary = JSON.parse(await readFile(summaryFile, "utf8"));
  assert.equal(correlated.length, 1);
  assert.equal(correlated[0].garnet.status, "path-observed");
  assert.equal(correlated[0].garnet.captureStatus, "complete");
  assert.equal(correlated[0].garnet.networkDestinations[0].domain, "example.net");
  assert.deepEqual(summary, {
    total: 1,
    "behavior-observed": 0,
    "path-observed": 1,
    "not-observed": 0,
    "unable-to-verify": 0,
  });
  assert.equal(correlated[0].garnet.correlatedRuns[0].runId, "garnet-profile-demo");
  assert.equal(requests.length, 4);
  assert.equal(
    requests[0],
    "GET /v1/runs/garnet-profile-demo/profile",
    "correlation must bind to the explicitly requested run",
  );

  console.log("DeepSec harness loaded @garnet-org/deepsec-plugin from deepsec.config.ts");
  console.log("DeepSec exported 1 finding from its native data mirror");
  console.log("DeepSec invoked garnet-correlate through its plugin command registry");
  console.log("Garnet enrichment: path-observed, destination example.net");
  console.log("Backend for this harness contract test: deterministic fixture server");
} finally {
  await new Promise((resolveClosed, rejectClosed) =>
    server.close((error) => (error ? rejectClosed(error) : resolveClosed())),
  );
}

function deepsec(args, childEnv) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [deepsecCli, ...args], {
      cwd: repo,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      process.stderr.write(chunk);
    });
    child.on("error", rejectRun);
    child.on("exit", (code) => {
      if (code === 0) resolveRun(stdout);
      else rejectRun(new Error(`deepsec ${args.join(" ")} exited ${code}\n${stderr}`));
    });
  });
}
