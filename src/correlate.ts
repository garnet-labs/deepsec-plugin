import type { GarnetClient } from "./garnet-client.js";
import type {
  GarnetDetection,
  GarnetEvent,
  GarnetFlow,
  GarnetProfileEnvelope,
  RuntimeCorrelation,
} from "./types/garnet.js";

export interface FindingLike {
  filePath: string;
  lineNumbers?: number[];
}

export interface CorrelateOptions {
  repository: string;
  runId: string;
  agentId?: string;
  stepName?: string;
}

export async function correlateFindingToRuntime(
  client: GarnetClient,
  finding: FindingLike,
  opts: CorrelateOptions,
): Promise<RuntimeCorrelation> {
  let exactProfiles: GarnetProfileEnvelope[];
  try {
    exactProfiles = opts.agentId
      ? (await client.getProfilesForAgent(opts.agentId, opts.runId)).items
      : [await client.getProfile(opts.runId)];
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return emptyCorrelation(
      `Garnet profile for run ${opts.runId} unavailable: ${message}`,
      [`Garnet profile for run ${opts.runId} unavailable: ${message}`],
    );
  }

  if (exactProfiles.length === 0) {
    const limitation = `Garnet profile for run ${opts.runId} unavailable: no matching profile`;
    return emptyCorrelation(limitation, [limitation]);
  }

  for (const profile of exactProfiles) {
    const profileRepository = `${profile.githubOrg}/${profile.repo}`;
    if (
      profileRepository.toLowerCase() !== opts.repository.toLowerCase() ||
      profile.runID !== opts.runId
    ) {
      const limitation =
        `Garnet profile ${profile.id} belongs to ${profileRepository} run ${profile.runID}, ` +
        `expected ${opts.repository} run ${opts.runId}`;
      return emptyCorrelation(limitation, [limitation]);
    }
  }

  const runs = exactProfiles.map((profile) => ({
    runId: profile.runID,
    workflowName: profile.job,
    startedAt: profile.createdAt,
  }));

  const events: GarnetEvent[] = [];
  const flows: GarnetFlow[] = [];
  const detections: GarnetDetection[] = [];
  const limitations: string[] = [];

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
            executionChain: renderExecutionChain(
              matchingTrees[0],
              name ?? peer.remote_address,
              Number.parseInt(port ?? "0", 10) || 0,
            ),
          });
        }
      }
    }
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
      executionChain: flow.executionChain,
      executionChains: [],
    };
    current.bytesOut += flow.bytesOut;
    if (flow.executionChain && !current.executionChains?.includes(flow.executionChain)) {
      current.executionChains?.push(flow.executionChain);
    }
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

function renderExecutionChain(
  tree: {
    ancestry?: string[];
    arguments?: string;
    executable?: string;
    process?: string;
  },
  destination: string | undefined,
  port: number,
): string | undefined {
  if (!destination) return undefined;
  const ancestry = tree.ancestry ?? [];
  const runnerWorkerIndex = ancestry.findIndex(
    (value) => commandLabel(value)?.basename === "Runner.Worker",
  );
  const retainedAncestry =
    runnerWorkerIndex === -1 ? ancestry : ancestry.slice(runnerWorkerIndex + 1);
  const commands = retainedAncestry
    .map(commandLabel)
    .filter((value): value is { label: string; basename: string } => value !== undefined);
  const leaf = commandLabel(tree.arguments ?? tree.executable ?? tree.process ?? "");
  if (leaf?.basename === commands.at(-1)?.basename) commands.pop();
  if (leaf) commands.push(leaf);
  const suffix = `${destination}:${port}`;
  return [...commands.map((command) => command.label), suffix].join(" → ");
}

function commandLabel(value: string): { label: string; basename: string } | undefined {
  const normalized = value.replaceAll("\\", "/").trim();
  if (!normalized) return undefined;
  const [executable, ...args] = normalized.split(/\s+/);
  const basename = executable?.split("/").at(-1);
  return basename ? { basename, label: [basename, ...args].join(" ") } : undefined;
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
