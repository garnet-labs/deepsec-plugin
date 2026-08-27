export interface GarnetProfile {
  agentId: string;
  repository: string;
  workflowName: string;
  runId: string;
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
  comm: string;
  args?: string[];
  path?: string;
  destAddr?: string;
  destPort?: number;
  destDomain?: string;
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
  policyDecision: "allow" | "deny" | "observe";
}

export interface GarnetDetection {
  recipeSlug: string;
  severity: "low" | "medium" | "high" | "critical";
  ts: string;
  pid: number;
  comm: string;
  details: string;
  evidenceEventIds: string[];
}

export type RuntimeObservationStatus =
  | "behavior-observed"
  | "path-observed"
  | "not-observed"
  | "unable-to-verify";

export interface RuntimeCorrelation {
  pathExecuted: boolean;
  executionCount: number;
  filesAccessed: string[];
  networkDestinations: Array<{
    domain?: string;
    addr: string;
    port: number;
    bytesOut: number;
  }>;
  detections: GarnetDetection[];
  correlatedRuns: Array<{ runId: string; workflowName: string; startedAt: string }>;
  status: RuntimeObservationStatus;
  captureStatus: "complete" | "partial" | "none";
  limitations: string[];
  reasoning: string;
}
