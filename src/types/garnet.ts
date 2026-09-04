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

export interface GarnetProcessTree {
  ancestry?: string[];
  arguments?: string;
  executable?: string;
  github_step?: string;
  pid?: number;
  process?: string;
}

export interface GarnetPeer {
  detections?: string[] | null;
  proc_trees?: GarnetProcessTree[];
  protocol?: string;
  remote_address?: string;
  remote_names?: string[];
  remote_ports?: string[];
  result?: "pass" | "attention" | "fail";
}

export interface GarnetProfileEnvelope {
  id: string;
  agentID: string;
  organization: string;
  repository: string;
  job: string;
  runID: string;
  createdAt: string;
  data?: {
    network?: {
      egress?: { peers?: GarnetPeer[] };
      ingress?: { peers?: GarnetPeer[] };
      local?: { peers?: GarnetPeer[] };
    };
  } | null;
}

export interface GarnetProfilePage {
  items: GarnetProfileEnvelope[];
  pageInfo: {
    totalCount: number;
    hasNextPage: boolean;
    hasPreviousPage: boolean;
  };
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
  executionChain?: string;
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
    executionChain?: string;
    executionChains?: string[];
  }>;
  detections: GarnetDetection[];
  correlatedRuns: Array<{ runId: string; workflowName: string; startedAt: string }>;
  status: RuntimeObservationStatus;
  captureStatus: "complete" | "partial" | "none";
  limitations: string[];
  reasoning: string;
}
