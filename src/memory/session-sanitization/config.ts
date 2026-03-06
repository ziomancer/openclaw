import { resolveSandboxRuntimeStatus } from "../../agents/sandbox/runtime-status.js";
import { parseDurationMs } from "../../cli/parse-duration.js";
import type { OpenClawConfig } from "../../config/config.js";
import { resolveAgentModelPrimaryValue } from "../../config/model-input.js";
import type { AgentModelConfig } from "../../config/types.agents-shared.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { normalizeAgentId } from "../../routing/session-key.js";

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

/**
 * Resolve the server name for a given tool by scanning `cfg.mcpServers`.
 * Returns the server identifier if a server claims the tool, or
 * `UNKNOWN_MCP_SERVER` ("unknown") when no server claims it.
 *
 * Lookup is by exact tool-name match.  The first server whose `tools` list
 * contains the tool name wins (iteration order = config declaration order).
 */
export function resolveToolServer(cfg: OpenClawConfig | undefined, toolName: string): string {
  const registry = cfg?.mcpServers;
  if (!registry || typeof registry !== "object") {
    return UNKNOWN_MCP_SERVER;
  }
  for (const [serverName, entry] of Object.entries(registry)) {
    if (
      Array.isArray(entry?.tools) &&
      entry.tools.some((t) => typeof t === "string" && (t === toolName || toolName.startsWith(t)))
    ) {
      return serverName;
    }
  }
  return UNKNOWN_MCP_SERVER;
}
