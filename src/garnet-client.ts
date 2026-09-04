// Thin client over api.garnet.ai. Read-only.
// In a real release this lives behind a versioned client SDK; this is the
// minimal shape needed to make the plugin runnable end-to-end.

import type {
  GarnetProfile,
  GarnetProfileEnvelope,
  GarnetProfilePage,
  GarnetEvent,
  GarnetFlow,
  GarnetDetection,
} from "./types/garnet.js";

export interface GarnetClientOptions {
  baseUrl?: string;             // default: https://api.garnet.ai
  apiToken: string;             // GARNET_API_TOKEN
  fetchImpl?: typeof fetch;
}

export class GarnetClient {
  private base: string;
  private token: string;
  private f: typeof fetch;

  constructor(opts: GarnetClientOptions) {
    this.base = opts.baseUrl ?? "https://api.garnet.ai";
    this.token = opts.apiToken;
    this.f = opts.fetchImpl ?? fetch;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.f(`${this.base}${path}`, {
      headers: { "X-Project-Token": this.token, accept: "application/json" },
    });
    if (!res.ok) throw new Error(`garnet api ${path}: ${res.status} ${res.statusText}`);
    return (await res.json()) as T;
  }

  /** Fetch the canonical profile envelope for a single workflow run. */
  getProfile(runId: string) {
    return this.get<GarnetProfileEnvelope>(`/api/v1/profiles/${encodeURIComponent(runId)}`);
  }

  /** Fetch canonical profiles for the action-created agent, bound to one workflow run. */
  getProfilesForAgent(agentId: string, runId: string) {
    const q = new URLSearchParams({ run_id: runId, first: "20" });
    return this.get<GarnetProfilePage>(
      `/api/v1/agents/${encodeURIComponent(agentId)}/profiles?${q}`,
    );
  }

  /** Server-side filter: events in a profile that touched a specific file path. */
  getEventsForPath(runId: string, filePath: string) {
    const q = new URLSearchParams({ path: filePath });
    return this.get<GarnetEvent[]>(`/v1/runs/${encodeURIComponent(runId)}/events?${q}`);
  }

  /** Network flows by process tree rooted at any pid that touched filePath. */
  getFlowsForPath(runId: string, filePath: string) {
    const q = new URLSearchParams({ path: filePath });
    return this.get<GarnetFlow[]>(`/v1/runs/${encodeURIComponent(runId)}/flows?${q}`);
  }

  getDetectionsForPath(runId: string, filePath: string) {
    const q = new URLSearchParams({ path: filePath });
    return this.get<GarnetDetection[]>(`/v1/runs/${encodeURIComponent(runId)}/detections?${q}`);
  }
}
