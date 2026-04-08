import { afterEach, describe, expect, it, vi } from "vitest";
import * as replyModule from "../auto-reply/reply.js";
import type { OpenClawConfig } from "../config/config.js";
import { loadSessionStore, resolveMainSessionKey } from "../config/sessions.js";
import { runHeartbeatOnce } from "./heartbeat-runner.js";
import { seedSessionStore, withTempHeartbeatSandbox } from "./heartbeat-runner.test-utils.js";

vi.mock("./outbound/deliver.js", () => ({
  deliverOutboundPayloads: vi.fn().mockResolvedValue(undefined),
}));

afterEach(() => {
  vi.restoreAllMocks();
});

describe("runHeartbeatOnce – isolated session file clearing", () => {
  function makeCfg(tmpDir: string, storePath: string): OpenClawConfig {
    return {
      agents: {
        defaults: {
          workspace: tmpDir,
          heartbeat: {
            every: "5m",
            target: "whatsapp",
            isolatedSession: true,
          },
        },
      },
      channels: { whatsapp: { allowFrom: ["*"] } },
      session: { store: storePath },
    };
  }

  it("clears stale sessionFile from the isolated heartbeat entry", async () => {
    await withTempHeartbeatSandbox(
      async ({ tmpDir, storePath }) => {
        const cfg = makeCfg(tmpDir, storePath);
        const sessionKey = resolveMainSessionKey(cfg);
        const isolatedKey = `${sessionKey}:heartbeat`;

        // Seed with a session entry that has a stale sessionFile
        await seedSessionStore(storePath, sessionKey, {
          sessionId: "old-sid",
          updatedAt: Date.now() - 60_000,
          lastChannel: "whatsapp",
          lastProvider: "whatsapp",
          lastTo: "+1555",
        });

        // Also seed the heartbeat key with a stale sessionFile
        const storeBeforeSeed = loadSessionStore(storePath);
        storeBeforeSeed[isolatedKey] = {
          sessionId: "stale-hb-sid",
          updatedAt: Date.now() - 60_000,
          sessionFile: "/tmp/stale-transcript.jsonl",
        };
        const fs = await import("node:fs/promises");
        await fs.writeFile(storePath, JSON.stringify(storeBeforeSeed));

        const replySpy = vi.spyOn(replyModule, "getReplyFromConfig");
        replySpy.mockResolvedValue({ text: "HEARTBEAT_OK" });

        await runHeartbeatOnce({
          cfg,
          deps: { getQueueSize: () => 0, nowMs: () => Date.now() },
        });

        const storeAfter = loadSessionStore(storePath);
        const hbEntry = storeAfter[isolatedKey];
        expect(hbEntry).toBeDefined();
        // sessionFile must be cleared so resolveSessionFilePath derives a fresh path
        expect(hbEntry?.sessionFile).toBeUndefined();
        // sessionId should differ from the stale one (forceNew generates a new one)
        expect(hbEntry?.sessionId).not.toBe("stale-hb-sid");
      },
      { prefix: "openclaw-hb-iso-" },
    );
  });

  it("produces different session IDs across consecutive isolated runs", async () => {
    await withTempHeartbeatSandbox(
      async ({ tmpDir, storePath }) => {
        const cfg = makeCfg(tmpDir, storePath);
        const sessionKey = resolveMainSessionKey(cfg);
        const isolatedKey = `${sessionKey}:heartbeat`;

        await seedSessionStore(storePath, sessionKey, {
          updatedAt: Date.now(),
          lastChannel: "whatsapp",
          lastProvider: "whatsapp",
          lastTo: "+1555",
        });

        const replySpy = vi.spyOn(replyModule, "getReplyFromConfig");
        replySpy.mockResolvedValue({ text: "HEARTBEAT_OK" });

        // Run 1
        await runHeartbeatOnce({
          cfg,
          deps: { getQueueSize: () => 0, nowMs: () => Date.now() },
        });

        const store1 = loadSessionStore(storePath, { skipCache: true });
        const sid1 = store1[isolatedKey]?.sessionId;
        expect(sid1).toBeDefined();

        // Run 2
        replySpy.mockResolvedValue({ text: "HEARTBEAT_OK" });
        await runHeartbeatOnce({
          cfg,
          deps: { getQueueSize: () => 0, nowMs: () => Date.now() },
        });

        const store2 = loadSessionStore(storePath, { skipCache: true });
        const sid2 = store2[isolatedKey]?.sessionId;
        expect(sid2).toBeDefined();

        // Each run should get a unique session ID
        expect(sid1).not.toBe(sid2);
        // And neither run should leave a sessionFile behind
        expect(store2[isolatedKey]?.sessionFile).toBeUndefined();
      },
      { prefix: "openclaw-hb-iso-consec-" },
    );
  });
});
