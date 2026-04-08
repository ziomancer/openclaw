import type { resolveAgentConfig } from "../../agents/agent-scope.js";
import type { AgentDefaultsConfig } from "../../config/types.js";

type ResolvedAgentConfig = NonNullable<ReturnType<typeof resolveAgentConfig>>;

function extractCronAgentDefaultsOverride(agentConfigOverride?: ResolvedAgentConfig) {
  const {
    model: overrideModel,
    sandbox: _agentSandboxOverride,
    ...agentOverrideRest
  } = agentConfigOverride ?? {};
  return {
    overrideModel,
    definedOverrides: Object.fromEntries(
      Object.entries(agentOverrideRest).filter(([, value]) => value !== undefined),
    ) as Partial<AgentDefaultsConfig>,
  };
}

function mergeCronAgentModelOverride(params: {
  defaults: AgentDefaultsConfig;
  overrideModel: ResolvedAgentConfig["model"] | undefined;
}) {
  const nextDefaults: AgentDefaultsConfig = { ...params.defaults };
  const existingModel =
    nextDefaults.model && typeof nextDefaults.model === "object" ? nextDefaults.model : {};
  if (typeof params.overrideModel === "string") {
    nextDefaults.model = { ...existingModel, primary: params.overrideModel };
  } else if (params.overrideModel) {
    nextDefaults.model = { ...existingModel, ...params.overrideModel };
  }
  return nextDefaults;
}

export function buildCronAgentDefaultsConfig(params: {
  defaults?: AgentDefaultsConfig;
  agentConfigOverride?: ResolvedAgentConfig;
}) {
  const { overrideModel, definedOverrides } = extractCronAgentDefaultsOverride(
    params.agentConfigOverride,
  );
  // Keep sandbox overrides out of `agents.defaults` here. Sandbox resolution
  // already merges global defaults with per-agent overrides using `agentId`;
  // copying the agent sandbox into defaults clobbers global defaults and can
  // double-apply nested agent overrides during isolated cron runs.
  const merged = mergeCronAgentModelOverride({
    defaults: Object.assign({}, params.defaults, definedOverrides),
    overrideModel,
  });
  // Cron jobs are background automation with their own job-level timeout.
  // The LLM idle timeout (default 60 s) is designed for interactive sessions
  // and causes spurious failures on slower models or large-context cron runs
  // where first-token latency exceeds 60 s.  Disable it unless the user has
  // explicitly configured a value.  See: #62752
  if (merged.llm?.idleTimeoutSeconds === undefined) {
    merged.llm = Object.assign({}, merged.llm, { idleTimeoutSeconds: 0 });
  }
  return merged;
}
