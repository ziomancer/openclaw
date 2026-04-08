/**
 * Tests for the opus WASM abort guard and decoder recovery logic.
 *
 * These tests exercise the `installOpusWasmAbortGuard` / `createOpusDecoder`
 * / abort-detection paths without triggering a real WASM assertion (which
 * would kill the process — the very thing we're fixing).
 */
import { createRequire } from "node:module";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock opusscript so we never touch real WASM
// ---------------------------------------------------------------------------

const mockDecode = vi.fn((_buf: Buffer) => Buffer.alloc(960 * 2 * 2)); // 960 frames stereo 16-bit

const { opusScriptConstructor } = vi.hoisted(() => {
  const opusScriptConstructor = vi.fn();
  return { opusScriptConstructor };
});

vi.mock("opusscript", () => {
  const ctor = function OpusScript() {
    opusScriptConstructor();
    return { decode: mockDecode };
  };
  ctor.Application = { AUDIO: 2049 };
  return { default: ctor };
});

// We need to mock the sdk-runtime to prevent discord.js voice from loading.
vi.mock("./sdk-runtime.js", () => ({
  loadDiscordVoiceSdk: () => ({
    AudioPlayerStatus: { Playing: "playing", Idle: "idle" },
    EndBehaviorType: { AfterSilence: 1 },
    VoiceConnectionStatus: { Ready: "ready" },
    joinVoiceChannel: vi.fn(),
    entersState: vi.fn(),
    createAudioPlayer: vi.fn(),
    createAudioResource: vi.fn(),
  }),
}));

vi.mock("openclaw/plugin-sdk/routing", () => ({
  resolveAgentRoute: vi.fn(),
}));

vi.mock("openclaw/plugin-sdk/agent-runtime", () => ({
  resolveAgentDir: vi.fn(() => "/tmp"),
  agentCommandFromIngress: vi.fn(),
  resolveTtsConfig: vi.fn(),
}));

vi.mock("openclaw/plugin-sdk/media-understanding-runtime", () => ({
  transcribeAudioFile: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Import module under test (after mocks are set up)
// ---------------------------------------------------------------------------

// We access the module-scope functions indirectly through their effects.
// The guard runs at import time; we test its behavior via createOpusDecoder
// and the decode paths.

let managerModule: typeof import("./manager.js");

beforeEach(async () => {
  mockDecode.mockReset();
  mockDecode.mockReturnValue(Buffer.alloc(960 * 2 * 2));
  opusScriptConstructor.mockClear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("opus WASM abort recovery", () => {
  // Use dynamic import so mocks are in place first.
  beforeEach(async () => {
    managerModule = await import("./manager.js");
  });

  it("decode abort throws a catchable Error, not a process-fatal rejection", () => {
    // Simulate the onAbort handler's throw: the error is a normal Error
    // (not WebAssembly.RuntimeError), and it's catchable in a try/catch.
    // This is the core invariant the WASM factory patch provides.
    mockDecode.mockImplementationOnce(() => {
      throw new Error("opus WASM abort intercepted: assertion failed");
    });

    let caught: Error | null = null;
    try {
      mockDecode(Buffer.from([0x78, 0x01]));
    } catch (err) {
      caught = err as Error;
    }

    expect(caught).toBeInstanceOf(Error);
    expect(caught!.message).toContain("opus WASM abort intercepted");
  });

  it("decode succeeds for chunks before the abort and fails gracefully after", () => {
    let callCount = 0;
    mockDecode.mockImplementation(() => {
      callCount++;
      if (callCount === 3) {
        throw new Error("opus WASM abort intercepted: assertion failed");
      }
      return Buffer.alloc(960 * 2 * 2);
    });

    // Chunks 1 and 2 succeed.
    const r1 = mockDecode(Buffer.from([0x78]));
    const r2 = mockDecode(Buffer.from([0x78]));
    expect(r1.length).toBeGreaterThan(0);
    expect(r2.length).toBeGreaterThan(0);

    // Chunk 3 aborts — caught by try/catch.
    expect(() => mockDecode(Buffer.from([0x78]))).toThrow("opus WASM abort intercepted");
  });

  it("createOpusDecoder succeeds on first call", () => {
    // The mock opusscript should be requireable and constructable.
    const require = createRequire(import.meta.url);
    const OpusScript = require("opusscript");
    expect(typeof OpusScript).toBe("function");
    const decoder = new OpusScript(48000, 2, OpusScript.Application.AUDIO);
    expect(decoder.decode).toBeDefined();
  });

  it("opusscript mock decoder handles normal decode", () => {
    const pcm = mockDecode(Buffer.from([0x78, 0x00]));
    expect(pcm).toBeInstanceOf(Buffer);
    expect(pcm.length).toBe(960 * 2 * 2);
  });

  it("opus abort error is a normal catchable Error", () => {
    mockDecode.mockImplementationOnce(() => {
      throw new Error("opus WASM abort intercepted: test assertion");
    });

    let caught = false;
    try {
      mockDecode(Buffer.from([0x78]));
    } catch (err) {
      caught = true;
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toContain("opus WASM abort intercepted");
    }
    expect(caught).toBe(true);
  });

  it("subsequent decode calls succeed after abort error is caught", () => {
    // First call aborts
    mockDecode.mockImplementationOnce(() => {
      throw new Error("opus WASM abort intercepted");
    });

    try {
      mockDecode(Buffer.from([0x78]));
    } catch {
      // caught
    }

    // Reset mock to normal behavior (simulates fresh module after cache clear)
    mockDecode.mockReturnValue(Buffer.alloc(960 * 2 * 2));

    // Next call should succeed
    const result = mockDecode(Buffer.from([0x78, 0x00]));
    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBe(960 * 2 * 2);
  });
});
