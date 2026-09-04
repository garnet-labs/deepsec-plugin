import type { RuntimeCorrelation } from "../types/garnet.js";

const STATUS_TEXT: Record<RuntimeCorrelation["status"], string> = {
  "behavior-observed": "Behavior observed; review recorded evidence",
  "path-observed": "Code path observed in queried profiles",
  "not-observed": "Not observed in queried profiles",
  "unable-to-verify": "Unable to verify from available profiles",
};

function escapeMarkdown(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replace(/([`*_[\]<>|])/g, "\\$1")
    .replaceAll("@", "@\u200b");
}

function inlineCode(value: string): string {
  return `\`${value.replaceAll("`", "'").replace(/\s+/g, " ")}\``;
}

function tableCell(value: string): string {
  return escapeMarkdown(value).replace(/\r?\n/g, " ");
}

export function renderRuntimeBlock(correlation: RuntimeCorrelation): string {
  const lines = [
    "#### Garnet runtime observation",
    "",
    `**${STATUS_TEXT[correlation.status]}**`,
    "",
    `> ${escapeMarkdown(correlation.reasoning)}`,
    "",
    `Capture: ${correlation.captureStatus}`,
  ];

  if (correlation.limitations.length > 0) {
    lines.push("", "**Limitations:**");
    for (const limitation of correlation.limitations) {
      lines.push(`- ${escapeMarkdown(limitation)}`);
    }
  }

  if (correlation.detections.length > 0) {
    lines.push("", "**Recorded detections:**");
    for (const detection of correlation.detections) {
      lines.push(
        `- ${inlineCode(detection.recipeSlug)} (${escapeMarkdown(detection.severity)}): ` +
          escapeMarkdown(detection.details),
      );
    }
  }

  if (correlation.networkDestinations.length > 0) {
    const executionChains = [
      ...new Set(
        correlation.networkDestinations
          .flatMap((destination) => [
            ...(destination.executionChains ?? []),
            destination.executionChain,
          ])
          .filter((chain): chain is string => Boolean(chain)),
      ),
    ];
    if (executionChains.length > 0) {
      lines.push("", "**Execution chains:**");
      for (const chain of executionChains) lines.push(`- ${inlineCode(chain)}`);
    }
    lines.push(
      "",
      "**Recorded network destinations:**",
      "",
      "| Destination | Port | Bytes out |",
      "|---|---:|---:|",
    );
    for (const destination of correlation.networkDestinations) {
      lines.push(
        `| ${tableCell(destination.domain ?? destination.addr)} | ${destination.port} | ` +
          `${destination.bytesOut} |`,
      );
    }
  }

  if (correlation.correlatedRuns.length > 0) {
    lines.push(
      "",
      `<sub>Queried ${correlation.correlatedRuns.length} Garnet profile(s): ` +
        correlation.correlatedRuns
          .map((run) => inlineCode(run.workflowName))
          .join(", ") +
        "</sub>",
    );
  }
  return lines.join("\n");
}

export { escapeMarkdown };
