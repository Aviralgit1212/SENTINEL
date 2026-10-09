
import type { Evidence } from "../types/scan.js";
import type { JsonFacts } from "./jsonAnalyzer.js";
import { createEvidence } from "../utils/evidence.js";

export function buildJsonEvidence(
  facts: JsonFacts,
): Evidence[] {
  const evidence: Evidence[] = [];

  const add = (
    title: string,
    description: string,
    severity: "low" | "medium" | "high" | "critical",
    score: number,
    source = "json-static-analysis",
  ) => {
    evidence.push(
      createEvidence({
        category: "json-analysis",
        title,
        description,
        severity,
        score,
        source,
      }),
    );
  };

  if (!facts.supported) {
    add(
      "JSON analysis incomplete",
      facts.error ??
        "Sentinel could not fully analyze this JSON file.",
      "medium",
      10,
    );

    return evidence;
  }

  if ((facts.duplicateKeyCount ?? 0) > 0) {
    add(
      "Duplicate JSON keys",
      `Found ${facts.duplicateKeyCount} duplicate object key occurrence(s). Different parsers may interpret duplicate keys differently.`,
      "medium",
      8,
    );
  }

  if ((facts.promptInjectionCount ?? 0) > 0) {
    add(
      "Prompt-injection-like instructions",
      `Detected ${facts.promptInjectionCount} suspicious instruction pattern(s). This may indicate attempts to manipulate an AI system, but does not by itself prove malicious intent.`,
      "high",
      20,
    );
  }

  if ((facts.dangerousKeyCount ?? 0) > 0) {
    add(
      "Command-like JSON keys",
      `Found ${facts.dangerousKeyCount} key(s) associated with commands or executable behavior.`,
      "medium",
      10,
    );
  }

  if ((facts.secretIndicators?.length ?? 0) > 0) {
    add(
      "Possible credentials or secret material",
      `Detected ${facts.secretIndicators?.length} possible secret pattern type(s). Values are intentionally not included in this report.`,
      "high",
      25,
    );
  }

  if ((facts.sensitiveKeyCount ?? 0) > 0) {
    add(
      "Sensitive data fields",
      `Found ${facts.sensitiveKeyCount} sensitive field name(s), such as password or token fields. Their presence alone does not prove that valid credentials are exposed.`,
      "low",
      3,
    );
  }

  if ((facts.htmlScriptLikeCount ?? 0) > 0) {
    add(
      "HTML or script-like content",
      `Found ${facts.htmlScriptLikeCount} string(s) containing HTML or script-like markers.`,
      "medium",
      10,
    );
  }

  const indicators = facts.suspiciousIndicators ?? [];

  if (
    indicators.includes("shell-command-pattern") ||
    indicators.includes("dynamic-code-pattern") ||
    indicators.includes("encoded-payload-marker")
  ) {
    add(
      "Potentially executable content",
      "One or more strings match patterns associated with shell commands, dynamic code, or encoded payloads. Sentinel inspected the strings without executing them.",
      "high",
      20,
    );
  }

  if (
    indicators.includes("node-limit-exceeded") ||
    indicators.includes("nesting-depth-limit-exceeded") ||
    indicators.includes("string-count-limit-exceeded") ||
    indicators.includes("analysis-truncated")
  ) {
    add(
      "JSON analysis reached a safety limit",
      "Sentinel could not fully inspect the JSON structure because an analysis limit was reached.",
      "medium",
      10,
    );
  }

  return evidence;
}

/**
 * JSON-specific recommendation policy.
 *
 * A clean result is eligible for allow only when
 * antivirus explicitly reports clean, the file type
 * matches, analysis completed, and risk remains low.
 */
export function recommendationForJson(
  facts: JsonFacts,
  antivirusStatus: string,
  extensionMismatch: boolean,
  riskScore: number,
): "allow" | "review" | "block" {
  if (antivirusStatus === "threat") {
    return "block";
  }

  if (
    !facts.ok ||
    !facts.supported ||
    antivirusStatus !== "clean" ||
    extensionMismatch ||
    (facts.suspiciousIndicators?.length ?? 0) > 0 ||
    riskScore >= 15
  ) {
    return "review";
  }

  return "allow";
}