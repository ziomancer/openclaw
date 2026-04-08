import { describe, expect, it } from "vitest";
import type { AgentDefaultsConfig } from "../../config/types.js";
import { buildCronAgentDefaultsConfig } from "./run-config.js";

describe("buildCronAgentDefaultsConfig", () => {
  it("disables LLM idle timeout when not explicitly configured", () => {
    const result = buildCronAgentDefaultsConfig({ defaults: {} });
    expect(result.llm?.idleTimeoutSeconds).toBe(0);
  });

  it("disables LLM idle timeout when defaults are undefined", () => {
    const result = buildCronAgentDefaultsConfig({});
    expect(result.llm?.idleTimeoutSeconds).toBe(0);
  });

  it("preserves explicit LLM idle timeout from user config", () => {
    const defaults: AgentDefaultsConfig = {
      llm: { idleTimeoutSeconds: 120 },
    };
    const result = buildCronAgentDefaultsConfig({ defaults });
    expect(result.llm?.idleTimeoutSeconds).toBe(120);
  });

  it("preserves explicit LLM idle timeout of 0 (already disabled)", () => {
    const defaults: AgentDefaultsConfig = {
      llm: { idleTimeoutSeconds: 0 },
    };
    const result = buildCronAgentDefaultsConfig({ defaults });
    expect(result.llm?.idleTimeoutSeconds).toBe(0);
  });

  it("preserves other llm config when overriding idle timeout", () => {
    const defaults: AgentDefaultsConfig = {
      llm: { idleTimeoutSeconds: undefined } as AgentDefaultsConfig["llm"],
    };
    const result = buildCronAgentDefaultsConfig({ defaults });
    expect(result.llm?.idleTimeoutSeconds).toBe(0);
  });
});
