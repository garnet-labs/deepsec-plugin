// Shape of the runtime evidence Garnet exposes via api.garnet.ai.
// Mirrors the public read API of garnetctl.

export interface GarnetProfile {
  agentId: string;
  repository: string;        // "garnet-labs/dub"
  workflowName: string;      // "Playwright E2E Tests"
  runId: string;             // GitHub Actions run id (string, matches GITHUB_RUN_ID)
  jobId: string;
  startedAt: string;
  endedAt: string;
  events: GarnetEvent[];
  flows: GarnetFlow[];
  detections: GarnetDetection[];
}

export type GarnetEventKind =
  | "syscall.exec"
  | "syscall.openat"
  | "syscall.connect"
  | "process.spawn"
  | "file.read"
  | "file.write"
  | "network.tcp.connect"
  | "network.dns.query";

export interface GarnetEvent {
  kind: GarnetEventKind;
  ts: string;
  pid: number;
  ppid: number;
  comm: string;          // process name (e.g. "node", "pnpm")
  args?: string[];
  // Filesystem events
  path?: string;
  // Network events
  destAddr?: string;
  destPort?: number;
  destDomain?: string;   // resolved CNAME if present
  // Detection-recipe match (when this event triggered one)
  recipeSlug?: string;
}

export interface GarnetFlow {
  flowId: string;
  pid: number;
  comm: string;
  destAddr: string;
  destPort: number;
  destDomain?: string;
  bytesOut: number;
  bytesIn: number;
  startedAt: string;
  endedAt?: string;
  // True if the flow was blocked by an active network policy.
  policyDecision: "allow" | "deny" | "observe";
}

export interface GarnetDetection {
  recipeSlug: string;            // e.g. "reading_of_ssh_keys"
  severity: "low" | "medium" | "high" | "critical";
  ts: string;
  pid: number;
  comm: string;
  details: string;
  evidenceEventIds: string[];
}

// What this plugin emits per deepsec finding after correlation.
export interface RuntimeCorrelation {
  // Did any code path matching this finding's filePath actually fire?
  pathExecuted: boolean;
  // Number of process spawns that touched this file (heuristic via dynamic require trace).
  executionCount: number;
  // Files this finding's path opened during the run window (top 10).
  filesAccessed: string[];
  // Network destinations reached by the process tree that fired this path.
  networkDestinations: Array<{ domain?: string; addr: string; port: number; bytesOut: number }>;
  // Detections that fired during execution of this code path.
  detections: GarnetDetection[];
  // All Garnet runs we cross-referenced.
  correlatedRuns: Array<{ runId: string; workflowName: string }>;
  // Verdict the plugin proposes to deepsec's `revalidate` step.
  verdict:
    | "exploitable-runtime-confirmed"   // path fired + matching unsafe egress/file access observed
    | "reachable-but-no-abuse"          // path fired, no malicious behavior in this run
    | "unreachable-in-this-suite"       // path did not fire in any correlated run
    | "no-runtime-data";                // no Garnet profile available
  reasoning: string;
}
