// Thin client over api.garnet.ai. Read-only.
// In a real release this lives behind a versioned client SDK; this is the
// minimal shape needed to make the plugin runnable end-to-end.

import type { GarnetProfile, GarnetEvent, GarnetFlow, GarnetDetection } from "./types/garnet.js";

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
      headers: { authorization: `Bearer ${this.token}`, accept: "application/json" },
    });
    if (!res.ok) throw new Error(`garnet api ${path}: ${res.status} ${res.statusText}`);
    return (await res.json()) as T;
  }

  /** List recent runs for a GitHub repo, optionally filtered by workflow. */
  listRuns(repo: string, opts: { workflowName?: string; limit?: number } = {}) {
    const q = new URLSearchParams({ repository: repo });
    if (opts.workflowName) q.set("workflow_name", opts.workflowName);
    if (opts.limit) q.set("limit", String(opts.limit));
    return this.get<Array<{ runId: string; workflowName: string; startedAt: string }>>(
      `/v1/runs?${q}`,
    );
  }

  /** Fetch the full profile for a single run. */
  getProfile(runId: string) {
    return this.get<GarnetProfile>(`/v1/runs/${encodeURIComponent(runId)}/profile`);
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
