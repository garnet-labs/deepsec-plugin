import type { GarnetClient } from "./garnet-client.js";
import type {
  GarnetDetection,
  GarnetEvent,
  GarnetFlow,
  RuntimeCorrelation,
} from "./types/garnet.js";

export interface FindingLike {
  filePath: string;
  lineNumbers?: number[];
}

export interface CorrelateOptions {
  repository: string;
  workflowName?: string;
  maxRuns?: number;
  runId?: string;
  agentId?: string;
  stepName?: string;
}

export async function correlateFindingToRuntime(
  client: GarnetClient,
  finding: FindingLike,
  opts: CorrelateOptions,
): Promise<RuntimeCorrelation> {
  const exactProfiles = opts.runId
    ? opts.agentId
      ? (await client.getProfilesForAgent(opts.agentId, opts.runId)).items
      : [await client.getProfile(opts.runId)]
    : undefined;
  const runs = exactProfiles
    ? exactProfiles.map((profile) => ({
        runId: profile.runID,
        workflowName: profile.job,
        startedAt: profile.createdAt,
      }))
    : await client.listRuns(opts.repository, {
        workflowName: opts.workflowName,
        limit: opts.maxRuns ?? 5,
      });

  if (runs.length === 0) {
    return emptyCorrelation(
      "No Garnet profiles were available for this repository.",
      ["No execution profile could be queried, so runtime behavior is unable to be verified."],
    );
  }

  const events: GarnetEvent[] = [];
  const flows: GarnetFlow[] = [];
  const detections: GarnetDetection[] = [];
  const limitations: string[] = [];

  if (exactProfiles) {
    const normalizedPath = finding.filePath.replaceAll("\\", "/");
    const basename = normalizedPath.split("/").at(-1) ?? normalizedPath;
    for (const profile of exactProfiles) {
      const peers = profile.data?.network?.egress?.peers ?? [];
      for (const peer of peers) {
        const matchingTrees = (peer.proc_trees ?? []).filter((tree) => {
          const pathMatch = [
            tree.executable,
            tree.arguments,
            tree.process,
            ...(tree.ancestry ?? []),
          ].some(
            (value) =>
              value?.replaceAll("\\", "/").includes(normalizedPath) ||
              value?.includes(basename),
          );
          const stepMatch =
            opts.stepName !== undefined &&
            tree.github_step?.toLowerCase().includes(opts.stepName.toLowerCase());
          return pathMatch || stepMatch;
        });
        if (matchingTrees.length === 0) continue;
        for (const tree of matchingTrees) {
          events.push({
            kind: "process.spawn",
            ts: profile.createdAt,
            pid: tree.pid ?? 0,
            ppid: 0,
            comm: tree.process ?? tree.executable ?? "unknown",
            path: finding.filePath,
          });
        }
        const names = peer.remote_names?.length ? peer.remote_names : [undefined];
        const ports = peer.remote_ports?.length ? peer.remote_ports : ["0"];
        for (const name of names) {
          for (const port of ports) {
            flows.push({
              flowId: `${profile.id}:${peer.remote_address ?? name ?? "unknown"}:${port}`,
              pid: matchingTrees[0]?.pid ?? 0,
              comm: matchingTrees[0]?.process ?? matchingTrees[0]?.executable ?? "unknown",
              destAddr: peer.remote_address ?? "",
              destPort: Number.parseInt(port ?? "0", 10) || 0,
              destDomain: name,
              bytesOut: 0,
              bytesIn: 0,
              startedAt: profile.createdAt,
              policyDecision: peer.result === "fail" ? "deny" : "observe",
            });
          }
        }
      }
    }
  } else for (const run of runs) {
    const results = await Promise.allSettled([
      client.getEventsForPath(run.runId, finding.filePath),
      client.getFlowsForPath(run.runId, finding.filePath),
      client.getDetectionsForPath(run.runId, finding.filePath),
    ]);
    const labels = ["events", "flows", "detections"] as const;
    const targets = [events, flows, detections] as Array<
      GarnetEvent[] | GarnetFlow[] | GarnetDetection[]
    >;

    results.forEach((result, index) => {
      if (result.status === "fulfilled") {
        targets[index]!.push(...(result.value as never[]));
      } else {
        limitations.push(`${run.runId}: ${labels[index]} evidence was unavailable`);
      }
    });
  }

  const pathExecuted = events.length > 0;
  const deniedFlows = flows.filter((flow) => flow.policyDecision === "deny");
  const captureStatus = limitations.length > 0 ? "partial" : "complete";

  const destinationMap = new Map<
    string,
    RuntimeCorrelation["networkDestinations"][number]
  >();
  for (const flow of flows) {
    const key = `${flow.destDomain ?? ""}|${flow.destAddr}|${flow.destPort}`;
    const current = destinationMap.get(key) ?? {
      domain: flow.destDomain,
      addr: flow.destAddr,
      port: flow.destPort,
      bytesOut: 0,
    };
    current.bytesOut += flow.bytesOut;
    destinationMap.set(key, current);
  }

  const networkDestinations = [...destinationMap.values()]
    .sort((a, b) => b.bytesOut - a.bytesOut)
    .slice(0, 10);
  const filesAccessed = [...new Set(events.flatMap((event) => (event.path ? [event.path] : [])))]
    .slice(0, 10);

  let status: RuntimeCorrelation["status"];
  let reasoning: string;
  if (detections.length > 0 || deniedFlows.length > 0) {
    status = "behavior-observed";
    reasoning =
      `Garnet returned ${detections.length} detection(s) and ${deniedFlows.length} denied ` +
      `egress attempt(s) attributed to the queried path. Review the recorded evidence; ` +
      `this observation is not an exploitability verdict.`;
  } else if (pathExecuted) {
    status = "path-observed";
    reasoning =
      `Garnet returned ${events.length} file-attributed runtime event(s) across ` +
      `${runs.length} queried profile(s).`;
  } else if (captureStatus === "partial") {
    status = "unable-to-verify";
    reasoning =
      "No file-attributed runtime event was returned, but one or more evidence queries failed.";
  } else {
    status = "not-observed";
    reasoning =
      `No file-attributed runtime event was returned from ${runs.length} queried profile(s). ` +
      "This does not prove that the path is unreachable.";
  }

  return {
    pathExecuted,
    executionCount: events.filter((event) => event.kind === "process.spawn").length,
    filesAccessed,
    networkDestinations,
    detections,
    correlatedRuns: runs.map((run) => ({
      runId: run.runId,
      workflowName: run.workflowName,
      startedAt: run.startedAt,
    })),
    status,
    captureStatus,
    limitations,
    reasoning,
  };
}

function emptyCorrelation(reasoning: string, limitations: string[]): RuntimeCorrelation {
  return {
    pathExecuted: false,
    executionCount: 0,
    filesAccessed: [],
    networkDestinations: [],
    detections: [],
    correlatedRuns: [],
    status: "unable-to-verify",
    captureStatus: "none",
    limitations,
    reasoning,
  };
}
