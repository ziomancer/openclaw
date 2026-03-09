import { randomUUID } from "node:crypto";
import type { FinalizedMsgContext } from "../auto-reply/templating.js";
import type { OpenClawConfig } from "../config/config.js";
import type {
  PluginHookMessageContext,
  PluginHookMessageReceivedEvent,
  PluginHookMessageSentEvent,
} from "../plugins/types.js";
import type {
  MessagePreprocessedHookContext,
  MessageReceivedHookContext,
  MessageSentHookContext,
  MessageTranscribedHookContext,
} from "./internal-hooks.js";

export type CanonicalInboundMessageHookContext = {
  from: string;
  to?: string;
  content: string;
  body?: string;
  bodyForAgent?: string;
  transcript?: string;
  timestamp?: number;
  channelId: string;
  accountId?: string;
  conversationId?: string;
  messageId?: string;
  senderId?: string;
  senderName?: string;
  senderUsername?: string;
  senderE164?: string;
  provider?: string;
  surface?: string;
  threadId?: string | number;
  mediaPath?: string;
  mediaType?: string;
  originatingChannel?: string;
  originatingTo?: string;
  guildId?: string;
  channelName?: string;
  isGroup: boolean;
  groupId?: string;
};

export type CanonicalSentMessageHookContext = {
  to: string;
  content: string;
  success: boolean;
  error?: string;
  channelId: string;
  accountId?: string;
  conversationId?: string;
  messageId?: string;
  isGroup?: boolean;
  groupId?: string;
};

export function deriveInboundMessageHookContext(
  ctx: FinalizedMsgContext,
  overrides?: {
    content?: string;
    messageId?: string;
  },
): CanonicalInboundMessageHookContext {
  const content =
    overrides?.content ??
    (typeof ctx.BodyForCommands === "string"
      ? ctx.BodyForCommands
      : typeof ctx.RawBody === "string"
        ? ctx.RawBody
        : typeof ctx.Body === "string"
          ? ctx.Body
          : "");
  const channelId = (ctx.OriginatingChannel ?? ctx.Surface ?? ctx.Provider ?? "").toLowerCase();
  const conversationId = ctx.OriginatingTo ?? ctx.To ?? ctx.From ?? undefined;
  const isGroup = Boolean(ctx.GroupSubject || ctx.GroupChannel);
  return {
    from: ctx.From ?? "",
    to: ctx.To,
    content,
    body: ctx.Body,
    bodyForAgent: ctx.BodyForAgent,
    transcript: ctx.Transcript,
    timestamp:
      typeof ctx.Timestamp === "number" && Number.isFinite(ctx.Timestamp)
        ? ctx.Timestamp
        : undefined,
    channelId,
    accountId: ctx.AccountId,
    conversationId,
    messageId:
      overrides?.messageId ??
      ctx.MessageSidFull ??
      ctx.MessageSid ??
      ctx.MessageSidFirst ??
      ctx.MessageSidLast,
    senderId: ctx.SenderId,
    senderName: ctx.SenderName,
    senderUsername: ctx.SenderUsername,
    senderE164: ctx.SenderE164,
    provider: ctx.Provider,
    surface: ctx.Surface,
    threadId: ctx.MessageThreadId,
    mediaPath: ctx.MediaPath,
    mediaType: ctx.MediaType,
    originatingChannel: ctx.OriginatingChannel,
    originatingTo: ctx.OriginatingTo,
    guildId: ctx.GroupSpace,
    channelName: ctx.GroupChannel,
    isGroup,
    groupId: isGroup ? conversationId : undefined,
  };
}

export function buildCanonicalSentMessageHookContext(params: {
  to: string;
  content: string;
  success: boolean;
  error?: string;
  channelId: string;
  accountId?: string;
  conversationId?: string;
  messageId?: string;
  isGroup?: boolean;
  groupId?: string;
}): CanonicalSentMessageHookContext {
  return {
    to: params.to,
    content: params.content,
    success: params.success,
    error: params.error,
    channelId: params.channelId,
    accountId: params.accountId,
    conversationId: params.conversationId ?? params.to,
    messageId: params.messageId,
    isGroup: params.isGroup,
    groupId: params.groupId,
  };
}

export function toPluginMessageContext(
  canonical: CanonicalInboundMessageHookContext | CanonicalSentMessageHookContext,
): PluginHookMessageContext {
  return {
    channelId: canonical.channelId,
    accountId: canonical.accountId,
    conversationId: canonical.conversationId,
  };
}

export function toPluginMessageReceivedEvent(
  canonical: CanonicalInboundMessageHookContext,
): PluginHookMessageReceivedEvent {
  return {
    from: canonical.from,
    content: canonical.content,
    timestamp: canonical.timestamp,
    metadata: {
      to: canonical.to,
      provider: canonical.provider,
      surface: canonical.surface,
      threadId: canonical.threadId,
      originatingChannel: canonical.originatingChannel,
      originatingTo: canonical.originatingTo,
      messageId: canonical.messageId,
      senderId: canonical.senderId,
      senderName: canonical.senderName,
      senderUsername: canonical.senderUsername,
      senderE164: canonical.senderE164,
      guildId: canonical.guildId,
      channelName: canonical.channelName,
    },
  };
}

export function toPluginMessageSentEvent(
  canonical: CanonicalSentMessageHookContext,
): PluginHookMessageSentEvent {
  return {
    to: canonical.to,
    content: canonical.content,
    success: canonical.success,
    ...(canonical.error ? { error: canonical.error } : {}),
  };
}

export function toInternalMessageReceivedContext(
  canonical: CanonicalInboundMessageHookContext,
): MessageReceivedHookContext {
  return {
    from: canonical.from,
    content: canonical.content,
    timestamp: canonical.timestamp,
    channelId: canonical.channelId,
    accountId: canonical.accountId,
    conversationId: canonical.conversationId,
    messageId: canonical.messageId,
    metadata: {
      to: canonical.to,
      provider: canonical.provider,
      surface: canonical.surface,
      threadId: canonical.threadId,
      senderId: canonical.senderId,
      senderName: canonical.senderName,
      senderUsername: canonical.senderUsername,
      senderE164: canonical.senderE164,
      guildId: canonical.guildId,
      channelName: canonical.channelName,
    },
  };
}

export function toInternalMessageTranscribedContext(
  canonical: CanonicalInboundMessageHookContext,
  cfg: OpenClawConfig,
): MessageTranscribedHookContext & { cfg: OpenClawConfig } {
  const shared = toInternalInboundMessageHookContextBase(canonical);
  return {
    ...shared,
    transcript: canonical.transcript ?? "",
    cfg,
  };
}

export function toInternalMessagePreprocessedContext(
  canonical: CanonicalInboundMessageHookContext,
  cfg: OpenClawConfig,
): MessagePreprocessedHookContext & { cfg: OpenClawConfig } {
  const shared = toInternalInboundMessageHookContextBase(canonical);
  return {
    ...shared,
    transcript: canonical.transcript,
    isGroup: canonical.isGroup,
    groupId: canonical.groupId,
    cfg,
  };
}

function toInternalInboundMessageHookContextBase(canonical: CanonicalInboundMessageHookContext) {
  return {
    from: canonical.from,
    to: canonical.to,
    body: canonical.body,
    bodyForAgent: canonical.bodyForAgent,
    timestamp: canonical.timestamp,
    channelId: canonical.channelId,
    conversationId: canonical.conversationId,
    messageId: canonical.messageId,
    senderId: canonical.senderId,
    senderName: canonical.senderName,
    senderUsername: canonical.senderUsername,
    provider: canonical.provider,
    surface: canonical.surface,
    mediaPath: canonical.mediaPath,
    mediaType: canonical.mediaType,
  };
}

/**
 * Build a minimal CanonicalInboundMessageHookContext from an AgentMessage.
 * Returns null for non-user messages or messages with no extractable text content.
 * Used to feed embedded-runner transcript turns into the session sanitization pipeline.
 */
export function toCanonicalInboundMessageHookContext(
  message: import("@mariozechner/pi-agent-core").AgentMessage,
): CanonicalInboundMessageHookContext | null {
  const msg = message as { role?: unknown; content?: unknown; timestamp?: unknown };
  if (msg.role !== "user") {
    return null;
  }
  const rawContent = msg.content;
  const content =
    typeof rawContent === "string"
      ? rawContent
      : Array.isArray(rawContent)
        ? rawContent
            .filter(
              (c): c is { type: "text"; text: string } =>
                typeof c === "object" && c !== null && (c as { type?: string }).type === "text",
            )
            .map((c) => c.text)
            .join("\n")
        : "";
  if (!content) {
    return null;
  }
  const timestamp = typeof msg.timestamp === "number" ? msg.timestamp : Date.now();
  return {
    from: "user",
    content,
    channelId: "embedded",
    isGroup: false,
    timestamp,
    messageId: `${timestamp}-${randomUUID().slice(0, 8)}`,
  };
}

export function toInternalMessageSentContext(
  canonical: CanonicalSentMessageHookContext,
): MessageSentHookContext {
  return {
    to: canonical.to,
    content: canonical.content,
    success: canonical.success,
    ...(canonical.error ? { error: canonical.error } : {}),
    channelId: canonical.channelId,
    accountId: canonical.accountId,
    conversationId: canonical.conversationId,
    messageId: canonical.messageId,
    ...(canonical.isGroup != null ? { isGroup: canonical.isGroup } : {}),
    ...(canonical.groupId ? { groupId: canonical.groupId } : {}),
  };
}
