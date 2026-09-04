import { describe, expect, it } from "vitest";
import { renderRuntimeBlock } from "../notifiers/render.js";

describe("renderRuntimeBlock", () => {
  it("renders every distinct execution chain", () => {
    const output = renderRuntimeBlock({
      pathExecuted: true,
      executionCount: 2,
      filesAccessed: ["runtime-review/webhook-preview.mjs"],
      networkDestinations: [
        {
          domain: "api.dub.co",
          addr: "203.0.113.10",
          port: 443,
          bytesOut: 10,
          executionChain: "bash → node → api.dub.co:443",
          executionChains: ["bash → node → api.dub.co:443"],
        },
        {
          domain: "example.com",
          addr: "203.0.113.20",
          port: 443,
          bytesOut: 20,
          executionChain: "bash → node → example.com:443",
          executionChains: ["bash → node → example.com:443"],
        },
      ],
      detections: [],
      correlatedRuns: [],
      status: "path-observed",
      captureStatus: "complete",
      limitations: [],
      reasoning: "The reviewed path was observed.",
    });

    expect(output).toContain("**Execution chains:**");
    expect(output).toContain("- `bash → node → api.dub.co:443`");
    expect(output).toContain("- `bash → node → example.com:443`");
  });
});
