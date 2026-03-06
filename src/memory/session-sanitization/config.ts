import { resolveSandboxRuntimeStatus } from "../../agents/sandbox/runtime-status.js";
import { parseDurationMs } from "../../cli/parse-duration.js";
import type { OpenClawConfig } from "../../config/config.js";
import { resolveAgentModelPrimaryValue } from "../../config/model-input.js";
import type { AgentModelConfig } from "../../config/types.agents-shared.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { normalizeAgentId } from "../../routing/session-key.js";
import type { AuditVerbosity } from "./types.js";

const log = createSubsystemLogger("memory/session-sanitization/config");

const DEFAULT_RAW_MAX_AGE = "24h";
const DEFAULT_THINKING = "low";

export type ResolvedSessionSanitizationConfig = {
  enabled: boolean;
  model?: AgentModelConfig;
  thinking: string;
  rawMaxAge: string;
  rawMaxAgeMs: number;
};

export function resolveSessionSanitizationConfig(
  cfg: OpenClawConfig | undefined,
): ResolvedSessionSanitizationConfig {
  const raw = cfg?.memory?.sessions?.sanitization;
  const rawMaxAge = raw?.rawMaxAge?.trim() || DEFAULT_RAW_MAX_AGE;
  let parsedRawMaxAge: number;
  try {
    parsedRawMaxAge = parseDurationMs(rawMaxAge);
  } catch {
    log.warn(`Invalid rawMaxAge value "${rawMaxAge}", falling back to default`, {
      fallback: DEFAULT_RAW_MAX_AGE,
    });
    parsedRawMaxAge = parseDurationMs(DEFAULT_RAW_MAX_AGE);
  }
  return {
    enabled: raw?.enabled === true,
    model: raw?.model ?? cfg?.agents?.defaults?.subagents?.model ?? cfg?.agents?.defaults?.model,
    thinking: raw?.thinking?.trim() || DEFAULT_THINKING,
    rawMaxAge,
    rawMaxAgeMs:
      Number.isFinite(parsedRawMaxAge) && parsedRawMaxAge > 0
        ? parsedRawMaxAge
        : parseDurationMs(DEFAULT_RAW_MAX_AGE),
  };
}

export function buildSessionSanitizationHelperSessionKey(
  agentId: string,
  suffix = "helper",
): string {
  return `agent:${normalizeAgentId(agentId)}:session-memory-${suffix}`;
}

export function resolveSessionSanitizationAvailability(params: {
  cfg?: OpenClawConfig;
  agentId: string;
}): { available: boolean; helperSessionKey: string } {
  const helperSessionKey = buildSessionSanitizationHelperSessionKey(params.agentId);
  const runtime = resolveSandboxRuntimeStatus({
    cfg: params.cfg,
    sessionKey: helperSessionKey,
  });
  return {
    available: runtime.sandboxed,
    helperSessionKey,
  };
}

export function hasConfiguredSessionSanitizationModel(cfg?: OpenClawConfig): boolean {
  return Boolean(resolveAgentModelPrimaryValue(resolveSessionSanitizationConfig(cfg).model));
}

export type ResolvedSessionSanitizationMcpConfig = {
  enabled: boolean;
  trustedServers: string[];
  blockOnSandboxUnavailable: boolean;
};

export function resolveSessionSanitizationMcpConfig(
  cfg: OpenClawConfig | undefined,
): ResolvedSessionSanitizationMcpConfig {
  const mcp = cfg?.memory?.sessions?.sanitization?.mcp;
  return {
    enabled: mcp?.enabled === true,
    trustedServers: Array.isArray(mcp?.trustedServers) ? mcp.trustedServers : [],
    blockOnSandboxUnavailable: mcp?.blockOnSandboxUnavailable !== false,
  };
}

export function isMcpServerTrusted(params: {
  cfg: OpenClawConfig | undefined;
  server: string;
}): boolean {
  const { trustedServers } = resolveSessionSanitizationMcpConfig(params.cfg);
  return trustedServers.includes(params.server);
}

export const UNKNOWN_MCP_SERVER = "unknown";

// ---------------------------------------------------------------------------
// Resolved validation config
// ---------------------------------------------------------------------------

const DEFAULT_FREQUENCY_WEIGHTS: Record<string, number> = {
  "injection.*": 10,
  "structural.*": 5,
  "schema.extra-field": 8,
  "schema.type-mismatch": 6,
  "schema.missing-field": 4,
};

const DEFAULT_TWOPASS_HARD_BLOCK_RULES: string[] = [
  "injection.ignore-previous",
  "injection.system-override",
  "injection.role-switch-capability",
];

export type ResolvedValidationConfig = {
  syntactic: {
    enabled: boolean;
    /** Maximum raw payload size in bytes. Default: 524288 (512KB). */
    maxPayloadBytes: number;
    /** Maximum JSON nesting depth. Default: 10. */
    maxJsonDepth: number;
  };
  schema: {
    enabled: boolean;
  };
  twoPass: {
    /** When true, hard-block rules skip the semantic sub-agent. Default: false. */
    enabled: boolean;
    /** Rule IDs that trigger a definitive block without a semantic pass. */
    hardBlockRules: string[];
  };
  frequency: {
    enabled: boolean;
    /** Half-life for exponential decay scoring in milliseconds. Default: 60000. */
    halfLifeMs: number;
    /** Weight per rule ID prefix. Prefix patterns end with ".*". */
    weights: Record<string, number>;
    thresholds: {
      tier1: number;
      tier2: number;
      tier3: number;
    };
  };
  audit: {
    enabled: boolean;
    verbosity: AuditVerbosity;
    retentionDays: number;
    rawRetentionDays: number;
  };
};

export function resolveSessionSanitizationValidationConfig(
  cfg: OpenClawConfig | undefined,
): ResolvedValidationConfig {
  const raw = cfg?.memory?.sessions?.sanitization;
  const retentionDays = raw?.audit?.retentionDays ?? 30;
  return {
    syntactic: {
      enabled: raw?.syntactic?.enabled !== false,
      maxPayloadBytes: raw?.syntactic?.maxPayloadBytes ?? 524_288,
      maxJsonDepth: raw?.syntactic?.maxJsonDepth ?? 10,
    },
    schema: {
      enabled: raw?.schema?.enabled !== false,
    },
    twoPass: {
      enabled: raw?.twoPass?.enabled === true,
      hardBlockRules: Array.isArray(raw?.twoPass?.hardBlockRules)
        ? (raw.twoPass.hardBlockRules as string[])
        : DEFAULT_TWOPASS_HARD_BLOCK_RULES,
    },
    frequency: {
      enabled: raw?.frequency?.enabled !== false,
      halfLifeMs: raw?.frequency?.halfLifeMs ?? 60_000,
      weights:
        raw?.frequency?.weights && Object.keys(raw.frequency.weights).length > 0
          ? raw.frequency.weights
          : DEFAULT_FREQUENCY_WEIGHTS,
      thresholds: {
        tier1: raw?.frequency?.thresholds?.tier1 ?? 15,
        tier2: raw?.frequency?.thresholds?.tier2 ?? 30,
        tier3: raw?.frequency?.thresholds?.tier3 ?? 50,
      },
    },
    audit: {
      enabled: raw?.audit?.enabled !== false,
      verbosity: raw?.audit?.verbosity ?? "standard",
      retentionDays,
      rawRetentionDays: raw?.audit?.rawRetentionDays ?? retentionDays,
    },
  };
}

/**
 * Returns true when the tool name is claimed by at least one server in
 * `cfg.mcpServers`, either by exact name match or by prefix match (i.e. the
 * tool name starts with a declared prefix entry).
 *
 * Uses the same matching logic as `resolveToolServer` so the two functions
 * stay consistent.  Used as the MCP membership gate in `wrapMcpToolDefinitions`
 * to distinguish confirmed MCP tools from native OpenClaw / client tools.
 */
export function isMcpToolNameDeclared(cfg: OpenClawConfig | undefined, toolName: string): boolean {
  const registry = cfg?.mcpServers;
  if (!registry || typeof registry !== "object") return false;
  for (const entry of Object.values(registry)) {
    if (
      Array.isArray(entry?.tools) &&
      entry.tools.some((t) => typeof t === "string" && (t === toolName || toolName.startsWith(t)))
    ) {
      return true;
    }
  }
  return false;
}

const warnedAmbiguousTools = new Set<string>();

/**
 * Resolve the server name for a given tool by scanning `cfg.mcpServers`.
 * Returns the server identifier if a server claims the tool (by exact name or
 * prefix), or `UNKNOWN_MCP_SERVER` ("unknown") when no server claims it.
 *
 * Uses longest-match prefix resolution: when multiple servers have prefixes
 * that match the tool name, the most specific (longest) prefix wins. When two
 * or more servers have equal-length matching prefixes the result is ambiguous —
 * `UNKNOWN_MCP_SERVER` is returned, routing through full sanitization.
 */
export function resolveToolServer(cfg: OpenClawConfig | undefined, toolName: string): string {
  const registry = cfg?.mcpServers;
  if (!registry || typeof registry !== "object") {
    return UNKNOWN_MCP_SERVER;
  }

  let bestLength = -1;
  let bestServers: string[] = [];

  for (const [serverName, entry] of Object.entries(registry)) {
    if (!Array.isArray(entry?.tools)) continue;
    for (const t of entry.tools) {
      if (typeof t !== "string") continue;
      if (t === toolName || toolName.startsWith(t)) {
        const matchLength = t.length;
        if (matchLength > bestLength) {
          bestLength = matchLength;
          bestServers = [serverName];
        } else if (matchLength === bestLength && !bestServers.includes(serverName)) {
          bestServers.push(serverName);
        }
      }
    }
  }

  if (bestServers.length === 0) {
    return UNKNOWN_MCP_SERVER;
  }

  if (bestServers.length > 1) {
    if (!warnedAmbiguousTools.has(toolName)) {
      warnedAmbiguousTools.add(toolName);
      log.warn(
        `Ambiguous MCP tool prefix overlap detected for tool '${toolName}': servers [${bestServers.join(", ")}] have equal-length matching prefixes. Routing through full sanitization. To resolve, use exact tool names or ensure prefixes are unambiguous.`,
      );
    }
    return UNKNOWN_MCP_SERVER;
  }

  return bestServers[0]!;
}
