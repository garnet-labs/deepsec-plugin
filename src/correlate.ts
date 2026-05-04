// Core correlation logic: take a deepsec Finding (filePath + lineNumbers) and
// the most recent N Garnet runs for the repo, produce a RuntimeCorrelation.
//
// Decision rule:
//   - pathExecuted := any GarnetEvent(kind ∈ {file.read, file.write, syscall.openat,
//                                            syscall.exec, process.spawn})
//                     where event.path or event.args[*] contains the finding's filePath
//   - networkDestinations := flows whose pid is in the spawn-tree rooted at any pid
//                            from those events, deduped by (domain, addr, port)
//   - detections := detections where event.pid ∈ that pid set
//   - verdict mapping:
//       detections.length > 0  OR  any flow.policyDecision === "deny"
//                                                       → "exploitable-runtime-confirmed"
//       pathExecuted && no detections                   → "reachable-but-no-abuse"
//       !pathExecuted                                   → "unreachable-in-this-suite"
//       no profiles found                               → "no-runtime-data"

import type { GarnetClient } from "./garnet-client.js";
import type {
  GarnetProfile,
  GarnetEvent,
  GarnetFlow,
  GarnetDetection,
  RuntimeCorrelation,
} from "./types/garnet.js";

export interface FindingLike {
  filePath: string;
  lineNumbers?: number[];
}

export interface CorrelateOptions {
  repository: string;            // e.g. "garnet-labs/dub"
  workflowName?: string;         // optional pin
  maxRuns?: number;              // default 5
}

export async function correlateFindingToRuntime(
  client: GarnetClient,
  finding: FindingLike,
  opts: CorrelateOptions,
): Promise<RuntimeCorrelation> {
  const runs = await client.listRuns(opts.repository, {
    workflowName: opts.workflowName,
    limit: opts.maxRuns ?? 5,
  });

  if (runs.length === 0) {
    return emptyCorrelation("no-runtime-data", "No Garnet runs found for this repository.");
  }

  const merged = {
    events: [] as GarnetEvent[],
    flows: [] as GarnetFlow[],
    detections: [] as GarnetDetection[],
    correlatedRuns: runs.map((r) => ({ runId: r.runId, workflowName: r.workflowName })),
  };

  // Per-run, ask Garnet for events/flows/detections scoped to this filePath.
  // This avoids paging entire profiles client-side.
  for (const r of runs) {
    const [events, flows, detections] = await Promise.all([
      client.getEventsForPath(r.runId, finding.filePath).catch(() => []),
      client.getFlowsForPath(r.runId, finding.filePath).catch(() => []),
      client.getDetectionsForPath(r.runId, finding.filePath).catch(() => []),
    ]);
    merged.events.push(...events);
    merged.flows.push(...flows);
    merged.detections.push(...detections);
  }

  const pathExecuted = merged.events.length > 0;
  const denials = merged.flows.filter((f) => f.policyDecision === "deny");

  // Top 10 unique network destinations
  const destMap = new Map<string, RuntimeCorrelation["networkDestinations"][number]>();
  for (const f of merged.flows) {
    const key = `${f.destDomain ?? ""}|${f.destAddr}|${f.destPort}`;
    const cur = destMap.get(key) ?? {
      domain: f.destDomain,
      addr: f.destAddr,
      port: f.destPort,
      bytesOut: 0,
    };
    cur.bytesOut += f.bytesOut;
    destMap.set(key, cur);
  }
  const networkDestinations = [...destMap.values()]
    .sort((a, b) => b.bytesOut - a.bytesOut)
    .slice(0, 10);

  // Files touched by the process tree (heuristic: any file event during the window)
  const filesAccessed = [
    ...new Set(merged.events.filter((e) => e.path).map((e) => e.path!)),
  ].slice(0, 10);

  // Verdict
  let verdict: RuntimeCorrelation["verdict"];
  let reasoning: string;

  if (merged.detections.length > 0) {
    verdict = "exploitable-runtime-confirmed";
    reasoning = `Garnet captured ${merged.detections.length} detection(s) on the process tree that executed ${finding.filePath}: ${merged.detections.map((d) => d.recipeSlug).join(", ")}.`;
  } else if (denials.length > 0) {
    verdict = "exploitable-runtime-confirmed";
    reasoning = `Garnet's network policy denied ${denials.length} egress attempt(s) from the process tree that executed this code path. Top denied destination(s): ${denials.slice(0, 3).map((d) => `${d.destDomain ?? d.destAddr}:${d.destPort}`).join(", ")}.`;
  } else if (pathExecuted) {
    verdict = "reachable-but-no-abuse";
    reasoning = `Code path fired in ${merged.correlatedRuns.length} run(s); ${merged.events.length} runtime event(s) observed; no detections or policy denials in this window.`;
  } else {
    verdict = "unreachable-in-this-suite";
    reasoning = `No runtime events recorded against ${finding.filePath} across ${merged.correlatedRuns.length} recent run(s). Either the path is dead code, gated behind a feature flag, or not exercised by current CI.`;
  }

  return {
    pathExecuted,
    executionCount: merged.events.filter((e) => e.kind === "process.spawn").length,
    filesAccessed,
    networkDestinations,
    detections: merged.detections,
    correlatedRuns: merged.correlatedRuns,
    verdict,
    reasoning,
  };
}

function emptyCorrelation(
  verdict: RuntimeCorrelation["verdict"],
  reasoning: string,
): RuntimeCorrelation {
  return {
    pathExecuted: false,
    executionCount: 0,
    filesAccessed: [],
    networkDestinations: [],
    detections: [],
    correlatedRuns: [],
    verdict,
    reasoning,
  };
}
