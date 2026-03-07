import type { OpenClawConfig } from "../../../config/config.js";
import { resolveSessionSanitizationMcpConfig } from "../config.js";

export type ResolvedAlertingConfig = {
  enabled: boolean;
  channels: {
    webhook: {
      url: string | null;
      secret: string | null;
      retries: number;
      retryDelayMs: number;
      timeoutMs: number;
    };
  };
  suppression: { windowMs: number };
  rateLimit: { maxPerMinute: number; maxPerHour: number };
  retention: { days: number };
  payload: { recentContextMax: number };
  index: { ttlMs: number };
  rules: {
    syntacticFailBurst: { count: number; windowMs: number };
    trustedToolSchemaFail: { enabled: boolean };
    frequencyEscalation: { tier2: boolean; tier3: boolean };
    semanticCatchNoSyntacticFlag: { enabled: boolean; escalateAfter: number };
    writeFailSpike: { count: number; windowMs: number };
  };
  trustedServers: string[];
};

/** Minimum index TTL — must cover the largest rule window (Rule 4 semantic-catch, 24 h). */
const MIN_INDEX_TTL_MS = 24 * 60 * 60_000;

export function resolveAlertingConfig(cfg: OpenClawConfig | undefined): ResolvedAlertingConfig {
  const raw = cfg?.alerting;
  const mcp = resolveSessionSanitizationMcpConfig(cfg);
  const resolved: ResolvedAlertingConfig = {
    enabled: raw?.enabled !== false,
    channels: {
      webhook: {
        url: raw?.channels?.webhook?.url ?? null,
        secret: raw?.channels?.webhook?.secret ?? null,
        retries: raw?.channels?.webhook?.retries ?? 2,
        retryDelayMs: raw?.channels?.webhook?.retryDelayMs ?? 1000,
        timeoutMs: raw?.channels?.webhook?.timeoutMs ?? 5000,
      },
    },
    suppression: { windowMs: (raw?.suppression?.windowMinutes ?? 5) * 60_000 },
    rateLimit: {
      maxPerMinute: raw?.rateLimit?.maxPerMinute ?? 20,
      maxPerHour: raw?.rateLimit?.maxPerHour ?? 100,
    },
    retention: { days: raw?.retention?.days ?? 30 },
    payload: { recentContextMax: raw?.payload?.recentContextMax ?? 20 },
    index: { ttlMs: (raw?.index?.ttlMinutes ?? 1440) * 60_000 },
    rules: {
      syntacticFailBurst: {
        count: raw?.rules?.syntacticFailBurst?.count ?? 5,
        windowMs: (raw?.rules?.syntacticFailBurst?.windowMinutes ?? 10) * 60_000,
      },
      trustedToolSchemaFail: {
        enabled: raw?.rules?.trustedToolSchemaFail?.enabled !== false,
      },
      frequencyEscalation: {
        tier2: raw?.rules?.frequencyEscalation?.tier2?.enabled !== false,
        tier3: true, // tier3 (session termination) cannot be disabled
      },
      semanticCatchNoSyntacticFlag: {
        enabled: raw?.rules?.semanticCatchNoSyntacticFlag?.enabled !== false,
        escalateAfter: raw?.rules?.semanticCatchNoSyntacticFlag?.escalateAfter ?? 3,
      },
      writeFailSpike: {
        count: raw?.rules?.writeFailSpike?.count ?? 3,
        windowMs: (raw?.rules?.writeFailSpike?.windowMinutes ?? 5) * 60_000,
      },
    },
    trustedServers: mcp.trustedServers,
  };

  if (resolved.index.ttlMs < MIN_INDEX_TTL_MS) {
    throw new Error(
      `alerting.index.ttlMinutes must be >= 1440 (24 h) to cover the Rule 4 semantic-catch` +
        ` correlation window (got ${Math.round(resolved.index.ttlMs / 60_000)} min)`,
    );
  }

  return resolved;
}
