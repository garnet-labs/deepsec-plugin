import type { RuntimeCorrelation } from "../types/garnet.js";

const VERDICT_BADGE: Record<RuntimeCorrelation["verdict"], string> = {
  "exploitable-runtime-confirmed":
    "🔴 **Runtime evidence: exploitable** — observed by Garnet during CI",
  "reachable-but-no-abuse":
    "🟡 **Runtime evidence: reachable** — code path fires under tests, no abuse observed yet",
  "unreachable-in-this-suite":
    "⚪ **Runtime evidence: unreachable** — no observed execution in current CI suites (likely lower priority)",
  "no-runtime-data":
    "⚫ **Runtime evidence: unavailable** — no Garnet profile for this repository",
};

export function renderRuntimeBlock(c: RuntimeCorrelation): string {
  const lines: string[] = [];
  lines.push(`#### Garnet runtime correlation`);
  lines.push(``);
  lines.push(VERDICT_BADGE[c.verdict]);
  lines.push(``);
  lines.push(`> ${c.reasoning}`);
  lines.push(``);

  if (c.detections.length > 0) {
    lines.push(`**Detections fired:**`);
    for (const d of c.detections) {
      lines.push(`- \`${d.recipeSlug}\` (${d.severity}) — ${d.details}`);
    }
    lines.push(``);
  }

  if (c.networkDestinations.length > 0) {
    lines.push(`**Network destinations reached during execution:**`);
    lines.push(``);
    lines.push(`| Destination | Port | Bytes out |`);
    lines.push(`|---|---|---|`);
    for (const d of c.networkDestinations) {
      lines.push(`| ${d.domain ?? d.addr} | ${d.port} | ${d.bytesOut} |`);
    }
    lines.push(``);
  }

  if (c.correlatedRuns.length > 0) {
    lines.push(
      `<sub>Correlated against ${c.correlatedRuns.length} Garnet run(s): ${c.correlatedRuns
        .map((r) => `\`${r.workflowName}\``)
        .join(", ")}</sub>`,
    );
  }
  return lines.join("\n");
}
