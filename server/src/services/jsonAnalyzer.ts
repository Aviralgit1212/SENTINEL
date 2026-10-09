
import { spawn } from "node:child_process";
import { resolve } from "node:path";

export interface JsonFacts {
    ok: boolean;
    supported: boolean;
    error: string | null;
    fileSize: number;
    topLevelType?: string;
    nodeCount?: number;
    stringCount?: number;
    maxDepth?: number;
    duplicateKeyCount?: number;
    duplicateKeyExamples?: string[];
    urls?: string[];
    ipAddresses?: string[];
    promptInjectionCount?: number;
    promptInjectionTypes?: string[];
    secretIndicators?: string[];
    sensitiveKeyCount?: number;
    sensitiveKeyExamples?: string[];
    dangerousKeyCount?: number;
    dangerousKeyExamples?: string[];
    htmlScriptLikeCount?: number;
    suspiciousIndicators?: string[];
    analysisTruncated?: boolean;
}

const TIMEOUT_MS = 15_000;
const MAX_STDOUT_BYTES = 1_000_000;
const MAX_STDERR_BYTES = 16_384;

function unsupported(error: string, fileSize = 0): JsonFacts {
    return {
        ok: false,
        supported: false,
        error,
        fileSize,
        suspiciousIndicators: ["json-analysis-unavailable"],
    };
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value)
    );
}

function normalizeFacts(value: unknown): JsonFacts {
    if (!isRecord(value)) {
        return unsupported("Python analyzer returned an invalid response.");
    }

    if (
        typeof value.ok !== "boolean" ||
        typeof value.supported !== "boolean" ||
        typeof value.fileSize !== "number" ||
        !Number.isFinite(value.fileSize) ||
        value.fileSize < 0
    ) {
        return unsupported("Python analyzer returned an invalid response.");
    }

    if (value.error !== null && typeof value.error !== "string") {
        return unsupported("Python analyzer returned an invalid response.");
    }

    if (value.ok === false || value.supported === false) {
        return {
            ...unsupported(
                typeof value.error === "string"
                    ? value.error
                    : "JSON analysis could not be completed.",
                value.fileSize,
            ),
            ok: value.ok,
        };
    }

    const validCount = (field: string): boolean =>
        typeof value[field] === "number" &&
        Number.isInteger(value[field]) &&
        (value[field] as number) >= 0;

    const validStringArray = (field: string): boolean =>
        Array.isArray(value[field]) &&
        value[field].every((item) => typeof item === "string");

    const requiredCounts = [
        "nodeCount",
        "stringCount",
        "maxDepth",
        "duplicateKeyCount",
        "promptInjectionCount",
        "sensitiveKeyCount",
        "dangerousKeyCount",
        "htmlScriptLikeCount",
    ];

    const requiredArrays = [
        "duplicateKeyExamples",
        "urls",
        "ipAddresses",
        "promptInjectionTypes",
        "secretIndicators",
        "sensitiveKeyExamples",
        "dangerousKeyExamples",
        "suspiciousIndicators",
    ];

    if (
        typeof value.topLevelType !== "string" ||
        !["object", "array", "string", "number", "boolean", "null"].includes(
            value.topLevelType,
        ) ||
        requiredCounts.some((field) => !validCount(field)) ||
        requiredArrays.some((field) => !validStringArray(field)) ||
        typeof value.analysisTruncated !== "boolean"
    ) {
        return unsupported("Python analyzer returned incomplete results.", value.fileSize);
    }

    return value as unknown as JsonFacts;
}

/**
 * Analyze a JSON file using the Python static analyzer.
 *
 * This function never executes the uploaded file. It only passes its path
 * to analyze_json.py for bounded, static inspection.
 */
export async function analyzeJsonFile(
    filePath: string,
): Promise<JsonFacts> {
    if (!filePath || typeof filePath !== "string") {
        return unsupported("A valid JSON file path is required.");
    }

    // The script path is anchored to the server working directory.
    // Run this service with the server directory as process.cwd().
    const scriptPath = resolve(
        process.cwd(),
        "src",
        "scripts",
        "analyze_json.py",
    );

    return new Promise<JsonFacts>((resolveResult) => {
        let stdout = "";
        let stderr = "";
        let stderrBytes = 0;
        let stdoutBytes = 0;
        let settled = false;
        let timedOut = false;
        let outputExceeded = false;

        const finish = (result: JsonFacts): void => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            resolveResult(result);
        };

        let child;

        try {
            child = spawn("python3", [scriptPath, resolve(filePath)], {
                stdio: ["ignore", "pipe", "pipe"],
                shell: false,
                windowsHide: true,
            });
        } catch {
            finish(unsupported("Could not start the Python JSON analyzer."));
            return;
        }

        const timeout = setTimeout(() => {
            timedOut = true;
            child.kill("SIGKILL");
        }, TIMEOUT_MS);

        child.stdout.on("data", (chunk: Buffer) => {
            stdoutBytes += chunk.length;

            if (stdoutBytes > MAX_STDOUT_BYTES) {
                outputExceeded = true;
                child.kill("SIGKILL");
                return;
            }

            stdout += chunk.toString("utf8");
        });

        child.stderr.on("data", (chunk: Buffer) => {
            stderrBytes += chunk.length;

            if (stderrBytes <= MAX_STDERR_BYTES) {
                stderr += chunk.toString("utf8");
            }
        });

        child.on("error", () => {
            finish(unsupported("Could not start the Python JSON analyzer."));
        });

        child.on("close", (code) => {
            if (settled) return;

            if (timedOut) {
                finish(unsupported("JSON analysis timed out."));
                return;
            }

            if (outputExceeded) {
                finish(unsupported("JSON analyzer output exceeded its limit."));
                return;
            }

            if (code !== 0) {
                finish(
                    unsupported(
                        "JSON analyzer exited unexpectedly.",
                    ),
                );
                return;
            }

            try {
                const parsed: unknown = JSON.parse(stdout.trim());
                finish(normalizeFacts(parsed));
            } catch {
                finish(
                    unsupported(
                        "JSON analyzer returned invalid or incomplete output.",
                    ),
                );
            }
        });
    });
}