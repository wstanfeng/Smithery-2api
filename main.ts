const encoder = new TextEncoder();
const decoder = new TextDecoder();

type AuthCookie = {
  headerValue: string;
  expiresAt: number;
};

type StoredConfig = {
  appName: string;
  appVersion: string;
  description: string;
  chatApiUrl: string;
  apiMasterKey: string | null;
  apiRequestTimeout: number;
  knownModels: string[];
  supabaseProjectRef: string;
  authTokens: string[];
  adminPasswordHash: string;
};

type RuntimeConfig = {
  stored: StoredConfig;
  authCookies: AuthCookie[];
};

type LogEntry = {
  id: string;
  timestamp: number;
  message: string;
};

type UsageLogEntry = {
  id: string;
  timestamp: number;
  model: string;
  status: "success" | "error";
  detail?: string;
};

const DEFAULT_MODELS = [
  "claude-haiku-4.5",
  "claude-sonnet-4.5",
  "gpt-5",
  "gpt-5-mini",
  "gpt-5-nano",
  "gemini-2.5-flash-lite",
  "gemini-2.5-pro",
  "glm-4.6",
  "grok-4-fast-non-reasoning",
  "grok-4-fast-reasoning",
  "kimi-k2",
  "deepseek-reasoner",
];

const DEFAULT_ADMIN_PASSWORD = "123456";
const DEFAULT_SUPABASE_PROJECT_REF = "spjawbfpwezjfmicopsl";
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const CONFIG_KEY = ["config", "core"];
const SESSION_KEY_PREFIX = ["admin", "session"];
const LOG_KEY = ["admin", "logs"];
const MAX_LOG_ENTRIES = 200;
const USAGE_LOG_KEY = ["admin", "usage_logs"];
const MAX_USAGE_LOG_ENTRIES = 500;

function parseKnownModels(value: string | undefined | null): string[] {
  if (!value) {
    return DEFAULT_MODELS.slice();
  }

  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed.filter((item) => typeof item === "string");
    }
  } catch {
    // ignore JSON parse errors
  }

  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function collectEnvTokens(): string[] {
  const results: string[] = [];
  let index = 1;

  while (true) {
    const envKey = `SMITHERY_COOKIE_${index}`;
    const token = Deno.env.get(envKey);
    if (!token) {
      break;
    }
    results.push(token);
    index += 1;
  }

  return results;
}

function normalizeTokenValue(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Token 不能为空。");
  }

  if (trimmed.startsWith("{")) {
    try {
      const data = JSON.parse(trimmed);
      const accessToken = data?.access_token;
      if (typeof accessToken === "string" && accessToken.length > 0) {
        return accessToken;
      }
    } catch {
      // fallthrough
    }
    throw new Error("无法从 JSON 中提取 access_token 字段。");
  }

  return trimmed;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length < 2) {
    return null;
  }

  try {
    const base = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base.padEnd(base.length + (4 - (base.length % 4)) % 4, "=");
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    const json = decoder.decode(bytes);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function createAuthCookieFromToken(token: string, projectRef: string): AuthCookie {
  if (!token) {
    throw new Error("Token 不能为空。");
  }

  const payload = decodeJwtPayload(token) ?? {};
  const exp = typeof payload.exp === "number" ? payload.exp : 0;
  const iat = typeof payload.iat === "number" ? payload.iat : Math.floor(Date.now() / 1000);
  const expiresIn = exp > iat ? exp - iat : 3600;

  const userMetadata = typeof payload.user_metadata === "object" && payload.user_metadata !== null
    ? payload.user_metadata
    : null;

  const user = userMetadata ?? {
    id: payload.sub ?? null,
    email: payload.email ?? null,
    role: payload.role ?? null,
  };

  const cookieValueData = {
    access_token: token,
    refresh_token: null,
    token_type: "bearer",
    expires_in: expiresIn,
    expires_at: exp,
    user,
  };

  const cookieKey = `sb-${projectRef}-auth-token`;
  const cookieValue = JSON.stringify(cookieValueData);

  return {
    headerValue: `${cookieKey}=${cookieValue}`,
    expiresAt: exp,
  };
}

function buildRuntimeConfig(stored: StoredConfig): RuntimeConfig {
  const cookies: AuthCookie[] = [];

  for (const raw of stored.authTokens) {
    try {
      const token = normalizeTokenValue(raw);
      cookies.push(createAuthCookieFromToken(token, stored.supabaseProjectRef));
    } catch (error) {
      console.warn(
        `[WARN] 无法解析 Smithery Token: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  return {
    stored,
    authCookies: cookies,
  };
}

async function hashPassword(password: string): Promise<string> {
  const data = encoder.encode(password);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyPassword(password: string, expectedHash: string): Promise<boolean> {
  const hashed = await hashPassword(password);
  return hashed === expectedHash;
}

async function createDefaultStoredConfig(): Promise<StoredConfig> {
  const envTokens = collectEnvTokens();
  const normalizedTokens: string[] = [];

  for (const item of envTokens) {
    try {
      normalizedTokens.push(normalizeTokenValue(item));
    } catch (error) {
      console.warn(
        `[WARN] 环境变量 Token 无法使用: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  return {
    appName: Deno.env.get("APP_NAME") ?? "smithery-2api",
    appVersion: Deno.env.get("APP_VERSION") ?? "1.0.0",
    description:
      Deno.env.get("DESCRIPTION") ??
      "一个将 smithery.ai 转换为兼容 OpenAI 格式 API 的高性能代理，支持多账号、上下文和工具调用。",
    chatApiUrl: Deno.env.get("CHAT_API_URL") ?? "https://smithery.ai/api/chat",
    apiMasterKey: Deno.env.get("API_MASTER_KEY") ?? null,
    apiRequestTimeout: Number(Deno.env.get("API_REQUEST_TIMEOUT") ?? "180"),
    knownModels: parseKnownModels(Deno.env.get("KNOWN_MODELS")),
    supabaseProjectRef:
      Deno.env.get("SUPABASE_PROJECT_REF") ?? DEFAULT_SUPABASE_PROJECT_REF,
    authTokens: normalizedTokens,
    adminPasswordHash: await hashPassword(DEFAULT_ADMIN_PASSWORD),
  };
}

function mergeStoredConfig(existing: StoredConfig | undefined, defaults: StoredConfig): StoredConfig {
  if (!existing) {
    return defaults;
  }

  const { authCookieStrings, ...rest } = existing as Record<string, unknown>;

  const legacyTokens = Array.isArray(authCookieStrings)
    ? (authCookieStrings as unknown as string[])
    : [];

  const existingTokens = Array.isArray((rest as Record<string, unknown>).authTokens)
    ? ((rest as { authTokens: unknown[] }).authTokens.filter((item): item is string => typeof item === "string"))
    : [];

  const tokensSource = existingTokens.length > 0 ? existingTokens : legacyTokens;

  const normalizedTokens: string[] = [];
  for (const item of tokensSource) {
    try {
      normalizedTokens.push(normalizeTokenValue(item));
    } catch (error) {
      console.warn(
        `[WARN] 存储中的 Token 无法使用: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  return {
    ...defaults,
    ...rest,
    authTokens: normalizedTokens,
    adminPasswordHash: typeof (rest as Record<string, unknown>).adminPasswordHash === "string"
      ? (rest as { adminPasswordHash: string }).adminPasswordHash
      : defaults.adminPasswordHash,
  };
}

const kv = await Deno.openKv();

const defaults = await createDefaultStoredConfig();
const savedConfig = await kv.get<StoredConfig>(CONFIG_KEY);
const storedConfig = mergeStoredConfig(savedConfig.value ?? undefined, defaults);

if (!savedConfig.value) {
  await kv.set(CONFIG_KEY, storedConfig);
  console.log("[INFO] 已将默认配置写入 Deno KV。");
}

const savedLogs = await kv.get<LogEntry[]>(LOG_KEY);
if (!Array.isArray(savedLogs.value)) {
  await kv.set(LOG_KEY, []);
}

const savedUsageLogs = await kv.get<UsageLogEntry[]>(USAGE_LOG_KEY);
if (!Array.isArray(savedUsageLogs.value)) {
  await kv.set(USAGE_LOG_KEY, []);
}

let runtimeConfig: RuntimeConfig = buildRuntimeConfig(storedConfig);
let cookieIndex = 0;

function getRuntimeConfig(): RuntimeConfig {
  return runtimeConfig;
}

async function persistConfig(stored: StoredConfig) {
  const normalizedTokens = stored.authTokens.map((item) => normalizeTokenValue(item));
  const candidate: StoredConfig = {
    ...stored,
    authTokens: normalizedTokens,
  };

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = await kv.get<StoredConfig>(CONFIG_KEY);
    const atomic = kv.atomic();

    if (current.versionstamp) {
      atomic.check({ key: CONFIG_KEY, versionstamp: current.versionstamp });
    } else {
      atomic.check({ key: CONFIG_KEY, versionstamp: null });
    }

    atomic.set(CONFIG_KEY, structuredClone(candidate));
    const result = await atomic.commit();
    if (result.ok) {
      runtimeConfig = buildRuntimeConfig(structuredClone(candidate));
      cookieIndex = 0;
      return;
    }
  }

  throw new Error("保存配置失败，请稍后重试。");
}

async function appendLog(message: string) {
  const entry: LogEntry = {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    message,
  };

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = await kv.get<LogEntry[]>(LOG_KEY);
    const existing = Array.isArray(current.value) ? current.value : [];
    const next = [...existing, entry].slice(-MAX_LOG_ENTRIES);

    const atomic = kv.atomic();
    if (current.versionstamp) {
      atomic.check({ key: LOG_KEY, versionstamp: current.versionstamp });
    } else {
      atomic.check({ key: LOG_KEY, versionstamp: null });
    }

    atomic.set(LOG_KEY, next);
    const result = await atomic.commit();
    if (result.ok) {
      return;
    }
  }

  console.warn("[WARN] 追加日志失败，已超过最大重试次数。");
}

async function getLogs(): Promise<LogEntry[]> {
  const record = await kv.get<LogEntry[]>(LOG_KEY);
  if (Array.isArray(record.value)) {
    return record.value.slice().sort((a, b) => b.timestamp - a.timestamp);
  }
  return [];
}

async function appendUsageLog(entry: UsageLogEntry) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = await kv.get<UsageLogEntry[]>(USAGE_LOG_KEY);
    const existing = Array.isArray(current.value) ? current.value : [];
    const next = [...existing, entry].slice(-MAX_USAGE_LOG_ENTRIES);

    const atomic = kv.atomic();
    if (current.versionstamp) {
      atomic.check({ key: USAGE_LOG_KEY, versionstamp: current.versionstamp });
    } else {
      atomic.check({ key: USAGE_LOG_KEY, versionstamp: null });
    }

    atomic.set(USAGE_LOG_KEY, next);
    const result = await atomic.commit();
    if (result.ok) {
      return;
    }
  }

  console.warn("[WARN] 追加使用日志失败，已超过最大重试次数。");
}

async function getUsageLogs(): Promise<UsageLogEntry[]> {
  const record = await kv.get<UsageLogEntry[]>(USAGE_LOG_KEY);
  if (Array.isArray(record.value)) {
    return record.value.slice().sort((a, b) => b.timestamp - a.timestamp);
  }
  return [];
}

async function createSession(): Promise<string> {
  const sessionId = crypto.randomUUID();
  await kv.set([...SESSION_KEY_PREFIX, sessionId], true, { expireIn: SESSION_TTL_MS });
  return sessionId;
}

async function destroySession(sessionId: string) {
  await kv.delete([...SESSION_KEY_PREFIX, sessionId]);
}

async function isAuthenticated(request: Request): Promise<{ ok: boolean; sessionId: string | null }> {
  const cookieHeader = request.headers.get("cookie");
  if (!cookieHeader) {
    return { ok: false, sessionId: null };
  }

  const cookies = parseCookies(cookieHeader);
  const sessionId = cookies.get("admin_session");
  if (!sessionId) {
    return { ok: false, sessionId: null };
  }

  const record = await kv.get([...SESSION_KEY_PREFIX, sessionId]);
  if (record.value) {
    return { ok: true, sessionId };
  }

  return { ok: false, sessionId };
}

function parseCookies(cookieHeader: string): Map<string, string> {
  const map = new Map<string, string>();
  const parts = cookieHeader.split(";").map((item) => item.trim()).filter(Boolean);
  for (const part of parts) {
    const index = part.indexOf("=");
    if (index === -1) {
      continue;
    }
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    map.set(key, value);
  }
  return map;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function htmlResponse(html: string, status = 200, headers: HeadersInit = {}): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...headers,
    },
  });
}

function getNextCookie(): string {
  const config = getRuntimeConfig();
  if (config.authCookies.length === 0) {
    throw new Error("未配置任何 Smithery Token。");
  }
  const cookie = config.authCookies[cookieIndex % config.authCookies.length];
  cookieIndex = (cookieIndex + 1) % config.authCookies.length;
  return cookie.headerValue;
}

const doneChunk = encoder.encode("data: [DONE]\n\n");

function createChatCompletionChunk(
  requestId: string,
  model: string,
  content: string,
  finishReason: string | null = null,
) {
  return {
    id: requestId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        delta: { content },
        finish_reason: finishReason,
      },
    ],
  };
}

function createSseData(data: unknown): Uint8Array {
  return encoder.encode(`data: ${JSON.stringify(data)}\n\n`);
}

function convertMessagesToSmitheryFormat(messages: unknown) {
  if (!Array.isArray(messages)) {
    return [];
  }

  const result: Array<{
    role: string;
    parts: Array<{ type: string; text: string }>;
    id: string;
  }> = [];

  for (const item of messages) {
    if (typeof item !== "object" || item === null) {
      continue;
    }

    const role = Reflect.get(item, "role");
    const content = Reflect.get(item, "content");

    if (typeof role !== "string" || typeof content !== "string") {
      continue;
    }

    const id = `msg-${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
    result.push({
      role,
      parts: [{ type: "text", text: content }],
      id,
    });
  }

  return result;
}

function preparePayload(model: string, messages: ReturnType<typeof convertMessagesToSmitheryFormat>) {
  return {
    messages,
    tools: [],
    model,
    systemPrompt: "You are a helpful assistant.",
  };
}

function prepareSmitheryHeaders(cookie: string): HeadersInit {
  return {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Content-Type": "application/json",
    "Cookie": cookie,
    "Origin": "https://smithery.ai",
    "Referer": "https://smithery.ai/playground",
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "priority": "u=1, i",
    "sec-ch-ua":
      '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "x-posthog-distinct-id": "5905f6b4-d74f-46b4-9b4f-9dbbccb29bee",
    "x-posthog-session-id": "0199f71f-8c42-7f9a-ba3a-ff5999dd444a",
    "x-posthog-window-id": "0199f71f-8c42-7f9a-ba3a-ff5ab5b20a8e",
  };
}

function verifyApiKey(request: Request): Response | null {
  const masterKey = getRuntimeConfig().stored.apiMasterKey;
  if (!masterKey || masterKey === "1") {
    return null;
  }
  const authorization = request.headers.get("authorization");
  if (!authorization || !authorization.toLowerCase().startsWith("bearer ")) {
    return jsonResponse({ detail: "需要 Bearer Token 认证。" }, 401);
  }
  const token = authorization.slice(7).trim();
  if (token !== masterKey) {
    return jsonResponse({ detail: "无效的 API Key。" }, 403);
  }
  return null;
}

async function handleChatCompletions(request: Request): Promise<Response> {
  const authError = verifyApiKey(request);
  if (authError) {
    return authError;
  }

  const config = getRuntimeConfig();
  if (config.authCookies.length === 0) {
    return jsonResponse({ detail: "未配置 Smithery Token，请先在后台添加。" }, 500);
  }

  let requestData: Record<string, unknown>;
  try {
    requestData = await request.json();
  } catch {
    return jsonResponse({ detail: "请求体必须是合法的 JSON。" }, 400);
  }

  const messages = convertMessagesToSmitheryFormat(requestData.messages);
  const model = typeof requestData.model === "string"
    ? requestData.model
    : "claude-haiku-4.5";
  const requestId = `chatcmpl-${crypto.randomUUID()}`;
  const payload = preparePayload(model, messages);
  const cookie = getNextCookie();

  console.info("===================== [REQUEST TO SMITHERY (Stateless)] =====================");
  console.info(`URL: POST ${config.stored.chatApiUrl}`);
  console.info(`PAYLOAD:\n${JSON.stringify(payload, null, 2)}`);
  console.info("=============================================================================");

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let finalSent = false;
      const sendFinal = (content: string, finishReason: string | null = "stop") => {
        if (finalSent) {
          return;
        }
        controller.enqueue(
          createSseData(
            createChatCompletionChunk(requestId, model, content, finishReason),
          ),
        );
        controller.enqueue(doneChunk);
        finalSent = true;
      };

      const abortController = new AbortController();
      const timeoutId = setTimeout(
        () => abortController.abort(),
        config.stored.apiRequestTimeout * 1000,
      );
      let usageLogged = false;

      (async () => {
        try {
          const response = await fetch(config.stored.chatApiUrl, {
            method: "POST",
            headers: prepareSmitheryHeaders(cookie),
            body: JSON.stringify(payload),
            signal: abortController.signal,
          });

          clearTimeout(timeoutId);

          if (!response.ok) {
            const errorText = await response.text();
            console.error("==================== [RESPONSE FROM SMITHERY (ERROR)] ===================");
            console.error(`STATUS CODE: ${response.status}`);
            console.error(`RESPONSE BODY:\n${errorText}`);
            console.error("=================================================================");
            throw new Error(`Smithery 响应状态 ${response.status}`);
          }

          if (!response.body) {
            throw new Error("Smithery 响应缺少流式内容。");
          }

          const reader = response.body.getReader();
          let buffer = "";
          let remoteDone = false;

          const processBuffer = () => {
            while (true) {
              const eventEnd = buffer.indexOf("\n\n");
              if (eventEnd === -1) {
                break;
              }
              const rawEvent = buffer.slice(0, eventEnd);
              buffer = buffer.slice(eventEnd + 2);

              for (const rawLine of rawEvent.split("\n")) {
                const line = rawLine.trim();
                if (!line.startsWith("data:")) {
                  continue;
                }

                const dataStr = line.slice(5).trim();
                if (!dataStr) {
                  continue;
                }

                if (dataStr === "[DONE]") {
                  remoteDone = true;
                  return;
                }

                try {
                  const parsed = JSON.parse(dataStr);
                  if (parsed && parsed.type === "text-delta") {
                    const deltaContent = typeof parsed.delta === "string"
                      ? parsed.delta
                      : "";
                    controller.enqueue(
                      createSseData(
                        createChatCompletionChunk(requestId, model, deltaContent, null),
                      ),
                    );
                  }
                } catch (error) {
                  console.warn(
                    `[WARN] 无法解析 SSE 数据: ${dataStr} - ${
                      error instanceof Error ? error.message : String(error)
                    }`,
                  );
                }
              }
            }
          };

          while (!remoteDone) {
            const { value, done } = await reader.read();
            if (done) {
              break;
            }
            buffer += decoder.decode(value, { stream: true });
            processBuffer();
            if (remoteDone) {
              break;
            }
          }

          buffer += decoder.decode();
          if (!remoteDone && buffer.length > 0) {
            buffer += "\n\n";
            processBuffer();
          }

          sendFinal("", "stop");

          if (!usageLogged) {
            await appendUsageLog({
              id: requestId,
              timestamp: Date.now(),
              model,
              status: "success",
            });
            usageLogged = true;
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          console.error("[ERROR] 处理流式响应时发生错误:", message);
          sendFinal(`内部服务器错误: ${message}`);

          if (!usageLogged) {
            await appendUsageLog({
              id: requestId,
              timestamp: Date.now(),
              model,
              status: "error",
              detail: message.slice(0, 200),
            });
            usageLogged = true;
          }
        } finally {
          clearTimeout(timeoutId);
          controller.close();
        }
      })();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

async function handleModels(request: Request): Promise<Response> {
  const authError = verifyApiKey(request);
  if (authError) {
    return authError;
  }

  const config = getRuntimeConfig();
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    object: "list",
    data: config.stored.knownModels.map((name) => ({
      id: name,
      object: "model",
      created: now,
      owned_by: "smithery-proxy",
    })),
  };

  return jsonResponse(payload);
}

function handleRoot(): Response {
  const config = getRuntimeConfig();
  return jsonResponse({
    message: `欢迎来到 ${config.stored.appName} v${config.stored.appVersion}。服务运行正常。`,
  });
}
function renderLoginPage(message?: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <title>后台登录</title>
    <style>
      body { margin: 0; font-family: "Microsoft YaHei", sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
      .card { background: #fff; padding: 32px; border-radius: 16px; box-shadow: 0 16px 40px rgba(15, 23, 42, 0.15); width: 360px; }
      h1 { margin: 0 0 12px; text-align: center; font-size: 24px; color: #1f2937; }
      p.tip { text-align: center; color: #6b7280; margin-bottom: 24px; }
      label { display: block; font-size: 14px; color: #374151; margin-bottom: 8px; }
      input[type="password"] { width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #d1d5db; font-size: 16px; box-sizing: border-box; transition: border-color 0.2s ease, box-shadow 0.2s ease; }
      input[type="password"]:focus { border-color: #2563eb; outline: none; box-shadow: 0 0 0 3px rgba(37,99,235,0.2); }
      button { width: 100%; padding: 12px; border-radius: 10px; border: none; background: linear-gradient(120deg, #2563eb, #7c3aed); color: #fff; font-size: 16px; cursor: pointer; margin-top: 16px; }
      button:hover { filter: brightness(1.05); }
      .message { margin-top: 16px; text-align: center; color: #dc2626; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>后台登录</h1>
      <p class="tip">默认密码：<strong>${DEFAULT_ADMIN_PASSWORD}</strong></p>
      <form method="post" action="/admin/login">
        <label for="password">后台密码</label>
        <input id="password" name="password" type="password" required placeholder="请输入后台密码" />
        <button type="submit">登录</button>
      </form>
      ${message ? `<div class="message">${message}</div>` : ""}
    </div>
  </body>
</html>`;
}
function renderAdminPage(): string {
  const config = getRuntimeConfig();
  return `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <title>${config.stored.appName} 后台管理</title>
    <style>
      * { box-sizing: border-box; }
      body { margin: 0; font-family: "Microsoft YaHei", sans-serif; background: #f4f6fb; color: #0f172a; }
      header { background: linear-gradient(120deg, #2563eb, #7c3aed); color: #fff; padding: 32px; box-shadow: 0 20px 45px rgba(37, 99, 235, 0.35); }
      header h1 { margin: 0; font-size: 26px; }
      header p { margin: 12px 0 0; opacity: 0.85; }
      main { padding: 32px; max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px; }
      section { background: #fff; border-radius: 20px; padding: 28px; box-shadow: 0 18px 45px rgba(15, 23, 42, 0.12); }
      section h2 { margin: 0 0 16px; font-size: 20px; border-bottom: 1px solid #e2e8f0; padding-bottom: 12px; }
      label { display: block; font-weight: 600; margin-top: 18px; }
      input[type="text"], input[type="number"], input[type="password"], textarea {
        width: 100%; padding: 12px 14px; border-radius: 12px; border: 1px solid #d1d5db; font-size: 14px; margin-top: 6px; transition: border-color 0.2s ease, box-shadow 0.2s ease;
      }
      textarea { min-height: 120px; resize: vertical; font-family: Consolas, monospace; }
      input:focus, textarea:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.18); outline: none; }
      .token-list { display: flex; flex-direction: column; gap: 12px; margin-top: 12px; }
      .token-item { display: flex; gap: 12px; align-items: center; }
      .token-item input { flex: 1; }
      .token-item button { padding: 10px 14px; border-radius: 10px; border: none; cursor: pointer; font-weight: 600; background: #fee2e2; color: #b91c1c; }
      .token-item button:hover { filter: brightness(0.95); }
      .actions { margin-top: 24px; display: flex; gap: 12px; flex-wrap: wrap; }
      button.primary { padding: 12px 22px; border-radius: 999px; border: none; cursor: pointer; font-weight: 600; background: linear-gradient(120deg, #2563eb, #7c3aed); color: #fff; }
      button.secondary { padding: 12px 22px; border-radius: 999px; border: none; cursor: pointer; font-weight: 600; background: #f1f5f9; color: #0f172a; }
      button.success { padding: 12px 22px; border-radius: 999px; border: none; cursor: pointer; font-weight: 600; background: #10b981; color: #fff; }
      button.add { padding: 10px 16px; border-radius: 999px; border: none; cursor: pointer; font-weight: 600; background: #e0ecff; color: #1d4ed8; margin-top: 12px; }
      #message { margin-top: 16px; padding: 14px 18px; border-radius: 14px; display: none; }
      #message.success { display: block; background: #ecfdf5; color: #047857; }
      #message.error { display: block; background: #fef2f2; color: #b91c1c; }
      #logs { display: grid; gap: 12px; max-height: 280px; overflow: auto; margin-top: 8px; }
      .log-item { padding: 12px 14px; border-radius: 12px; background: #f8fafc; border: 1px solid #e2e8f0; font-size: 13px; line-height: 1.5; }
      .log-item time { display: block; font-size: 12px; color: #64748b; margin-bottom: 4px; }
      @media (max-width: 720px) {
        main { padding: 20px; }
        section { padding: 22px; }
        .token-item { flex-direction: column; align-items: stretch; }
        .token-item button { width: 100%; }
      }
    </style>
  </head>
  <body>
    <header>
      <h1>${config.stored.appName} 后台管理</h1>
      <p>版本 v${config.stored.appVersion} · 已加载 ${config.authCookies.length} 组 Token</p>
    </header>
    <main>
      <section>
        <h2>服务配置</h2>
        <form id="configForm">
          <label for="appName">应用名称</label>
          <input id="appName" name="appName" type="text" required />

          <label for="appVersion">应用版本</label>
          <input id="appVersion" name="appVersion" type="text" required />

          <label for="description">服务描述</label>
          <textarea id="description" name="description"></textarea>

          <label for="chatApiUrl">Smithery Chat API 地址</label>
          <input id="chatApiUrl" name="chatApiUrl" type="text" required />

          <label for="apiRequestTimeout">请求超时时间（秒）</label>
          <input id="apiRequestTimeout" name="apiRequestTimeout" type="number" min="10" max="600" step="1" required />

          <label for="apiMasterKey">API Master Key（留空表示关闭认证）</label>
          <input id="apiMasterKey" name="apiMasterKey" type="text" />

          <label for="supabaseProjectRef">Supabase Project Ref</label>
          <input id="supabaseProjectRef" name="supabaseProjectRef" type="text" required />

          <label for="knownModels">已知模型（每行一个或逗号分隔）</label>
          <textarea id="knownModels" name="knownModels"></textarea>

          <label>Smithery Access Tokens</label>
          <div class="token-list" id="tokenList"></div>
          <button class="add" type="button" id="addTokenBtn">+ 添加 Token</button>

          <div class="actions">
            <button class="primary" type="submit">保存配置</button>
            <button class="secondary" type="button" id="logoutBtn">退出登录</button>
          </div>
        </form>
        <div id="message"></div>
      </section>

      <section>
        <h2>修改后台密码</h2>
        <form id="passwordForm">
          <label for="currentPassword">当前密码</label>
          <input id="currentPassword" name="currentPassword" type="password" required />

          <label for="newPassword">新密码（至少 6 位）</label>
          <input id="newPassword" name="newPassword" type="password" minlength="6" required />

          <div class="actions">
            <button class="success" type="submit">更新密码</button>
          </div>
        </form>
      </section>

      <section>
        <h2>操作日志</h2>
        <div id="logs"></div>
        <div class="actions">
          <button class="secondary" type="button" id="refreshLogsBtn">刷新日志</button>
        </div>
      </section>

      <section>
        <h2>模型调用日志</h2>
        <div id="usageLogs"></div>
        <div class="actions">
          <button class="secondary" type="button" id="refreshUsageLogsBtn">刷新调用日志</button>
        </div>
      </section>
    </main>

    <script>
      const messageBox = document.getElementById("message");
      const configForm = document.getElementById("configForm");
      const passwordForm = document.getElementById("passwordForm");
      const logoutBtn = document.getElementById("logoutBtn");
      const addTokenBtn = document.getElementById("addTokenBtn");
      const tokenList = document.getElementById("tokenList");
      const logsContainer = document.getElementById("logs");
      const usageLogsContainer = document.getElementById("usageLogs");
      const refreshLogsBtn = document.getElementById("refreshLogsBtn");
      const refreshUsageLogsBtn = document.getElementById("refreshUsageLogsBtn");

      function showMessage(type, text) {
        messageBox.className = type === "success" ? "success" : "error";
        messageBox.textContent = text;
      }

      function createTokenRow(value = "") {
        const wrapper = document.createElement("div");
        wrapper.className = "token-item";

        const input = document.createElement("input");
        input.type = "text";
        input.placeholder = "粘贴 Supabase Access Token";
        input.value = value;

        const removeBtn = document.createElement("button");
        removeBtn.type = "button";
        removeBtn.textContent = "删除";
        removeBtn.addEventListener("click", () => {
          tokenList.removeChild(wrapper);
          if (tokenList.children.length === 0) {
            tokenList.appendChild(createTokenRow());
          }
        });

        wrapper.append(input, removeBtn);
        return wrapper;
      }

      function setTokens(tokens) {
        tokenList.innerHTML = "";
        const list = Array.isArray(tokens) && tokens.length > 0 ? tokens : [""];
        for (const token of list) {
          tokenList.appendChild(createTokenRow(token));
        }
      }

      function collectTokens() {
        const inputs = tokenList.querySelectorAll("input");
        return Array.from(inputs)
          .map((input) => input.value.trim())
          .filter((value) => value.length > 0);
      }

      function renderLogs(logs) {
        logsContainer.innerHTML = "";
        if (!Array.isArray(logs) || logs.length === 0) {
          const empty = document.createElement("div");
          empty.className = "log-item";
          empty.textContent = "暂无日志记录。";
          logsContainer.appendChild(empty);
          return;
        }

        const sorted = logs.slice().sort((a, b) => b.timestamp - a.timestamp);
        for (const log of sorted) {
          const item = document.createElement("div");
          item.className = "log-item";
          const time = document.createElement("time");
          const date = new Date(log.timestamp);
          time.textContent = date.toLocaleString();
          const message = document.createElement("div");
          message.textContent = log.message;
          item.append(time, message);
          logsContainer.appendChild(item);
        }
      }

      async function loadConfig() {
        try {
          const res = await fetch("/admin/api/config");
          if (!res.ok) {
            throw new Error("无法获取配置");
          }
          const data = await res.json();
          document.getElementById("appName").value = data.appName ?? "";
          document.getElementById("appVersion").value = data.appVersion ?? "";
          document.getElementById("description").value = data.description ?? "";
          document.getElementById("chatApiUrl").value = data.chatApiUrl ?? "";
          document.getElementById("apiRequestTimeout").value = data.apiRequestTimeout ?? 180;
          document.getElementById("apiMasterKey").value = data.apiMasterKey ?? "";
          document.getElementById("supabaseProjectRef").value = data.supabaseProjectRef ?? "";
          document.getElementById("knownModels").value = (data.knownModels ?? []).join("\\n");
          setTokens(data.authTokens ?? data.authCookieStrings ?? []);
        } catch (error) {
          showMessage("error", error.message || "加载配置失败");
        }
      }

      async function loadLogs() {
        try {
          const res = await fetch("/admin/api/logs");
          if (!res.ok) {
            throw new Error("无法获取日志");
          }
          const data = await res.json();
          renderLogs(data.logs ?? []);
        } catch (error) {
          showMessage("error", error.message || "加载日志失败");
        }
      }

      function renderUsageLogs(logs) {
        usageLogsContainer.innerHTML = "";
        if (!Array.isArray(logs) || logs.length === 0) {
          const empty = document.createElement("div");
          empty.className = "log-item";
          empty.textContent = "暂无调用记录。";
          usageLogsContainer.appendChild(empty);
          return;
        }

        const sorted = logs.slice().sort((a, b) => b.timestamp - a.timestamp);
        for (const log of sorted) {
          const item = document.createElement("div");
          item.className = "log-item";

          const time = document.createElement("time");
          time.textContent = new Date(log.timestamp).toLocaleString();

          const summary = document.createElement("div");
          summary.textContent = \`模型：\${log.model} · 状态：\${log.status}\`;

          item.append(time, summary);

          if (log.detail) {
            const detail = document.createElement("div");
            detail.style.marginTop = "6px";
            detail.style.color = "#475569";
            detail.textContent = log.detail;
            item.append(detail);
          }

          usageLogsContainer.appendChild(item);
        }
      }

      async function loadUsageLogs() {
        try {
          const res = await fetch("/admin/api/usage");
          if (!res.ok) {
            throw new Error("无法获取调用日志");
          }
          const data = await res.json();
          renderUsageLogs(data.logs ?? []);
        } catch (error) {
          showMessage("error", error.message || "加载调用日志失败");
        }
      }

      configForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formData = new FormData(configForm);
        const tokens = collectTokens();

        if (tokens.length === 0) {
          showMessage("error", "请至少添加一个 Token。");
          return;
        }

        const payload = {
          appName: formData.get("appName"),
          appVersion: formData.get("appVersion"),
          description: formData.get("description"),
          chatApiUrl: formData.get("chatApiUrl"),
          apiRequestTimeout: Number(formData.get("apiRequestTimeout")),
          apiMasterKey: formData.get("apiMasterKey"),
          supabaseProjectRef: formData.get("supabaseProjectRef"),
          knownModels: String(formData.get("knownModels") || "")
            .split(/[\\n,]+/)
            .map((item) => item.trim())
            .filter((item) => item.length > 0),
          authTokens: tokens,
        };

        if (!payload.appName || !payload.appVersion || !payload.chatApiUrl || !payload.supabaseProjectRef) {
          showMessage("error", "请完整填写必要字段。");
          return;
        }

        if (!Number.isFinite(payload.apiRequestTimeout) || payload.apiRequestTimeout < 10) {
          showMessage("error", "请求超时至少为 10 秒。");
          return;
        }

        try {
          const res = await fetch("/admin/api/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          const data = await res.json();
          if (!res.ok) {
            throw new Error(data.detail || "保存失败");
          }
          showMessage("success", "配置已保存。");
          await Promise.all([loadConfig(), loadLogs(), loadUsageLogs()]);
        } catch (error) {
          showMessage("error", error.message || "保存配置失败");
        }
      });

      passwordForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formData = new FormData(passwordForm);
        const payload = {
          currentPassword: formData.get("currentPassword"),
          newPassword: formData.get("newPassword"),
        };

        if (!payload.currentPassword || !payload.newPassword) {
          showMessage("error", "请填写完整的密码信息。");
          return;
        }

        try {
          const res = await fetch("/admin/api/password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          const data = await res.json();
          if (!res.ok) {
            throw new Error(data.detail || "更新密码失败");
          }
          showMessage("success", "密码已更新，下次登录生效。");
          passwordForm.reset();
          await Promise.all([loadLogs(), loadUsageLogs()]);
        } catch (error) {
          showMessage("error", error.message || "更新密码失败");
        }
      });

      logoutBtn.addEventListener("click", async () => {
        await fetch("/admin/logout", { method: "POST" });
        window.location.href = "/admin";
      });

      addTokenBtn.addEventListener("click", () => {
        tokenList.appendChild(createTokenRow());
      });

      refreshLogsBtn.addEventListener("click", loadLogs);
      refreshUsageLogsBtn.addEventListener("click", loadUsageLogs);

      loadConfig();
      loadLogs();
      loadUsageLogs();
    </script>
  </body>
</html>`;
}
async function handleAdmin(request: Request): Promise<Response> {
  const { ok } = await isAuthenticated(request);
  if (!ok) {
    return htmlResponse(renderLoginPage());
  }
  return htmlResponse(renderAdminPage());
}

async function handleLogin(request: Request): Promise<Response> {
  const formData = await request.formData();
  const password = formData.get("password");
  if (typeof password !== "string") {
    return htmlResponse(renderLoginPage("请输入有效的密码"), 400);
  }

  const config = getRuntimeConfig();
  const correct = await verifyPassword(password, config.stored.adminPasswordHash);
  if (!correct) {
    await appendLog("管理员登录失败：密码错误。");
    return htmlResponse(renderLoginPage("密码错误，请重试"), 401);
  }

  const sessionId = await createSession();
  await appendLog("管理员登录成功。");
  return htmlResponse(renderAdminPage(), 200, {
    "Set-Cookie": `admin_session=${sessionId}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS / 1000}; SameSite=Lax`,
  });
}

async function handleLogout(request: Request): Promise<Response> {
  const auth = await isAuthenticated(request);
  if (auth.sessionId) {
    await destroySession(auth.sessionId);
  }
  await appendLog("管理员退出登录。");
  return htmlResponse(renderLoginPage("已退出登录"), 200, {
    "Set-Cookie": "admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax",
  });
}

async function handleConfigGet(request: Request): Promise<Response> {
  const { ok } = await isAuthenticated(request);
  if (!ok) {
    return jsonResponse({ detail: "未授权" }, 401);
  }

  const config = getRuntimeConfig().stored;
  return jsonResponse({
    appName: config.appName,
    appVersion: config.appVersion,
    description: config.description,
    chatApiUrl: config.chatApiUrl,
    apiMasterKey: config.apiMasterKey,
    apiRequestTimeout: config.apiRequestTimeout,
    knownModels: config.knownModels,
    supabaseProjectRef: config.supabaseProjectRef,
    authTokens: config.authTokens,
  });
}

async function handleConfigPost(request: Request): Promise<Response> {
  const { ok } = await isAuthenticated(request);
  if (!ok) {
    return jsonResponse({ detail: "未授权" }, 401);
  }

  let payload: Record<string, unknown>;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ detail: "请求体必须是 JSON" }, 400);
  }

  const appName = typeof payload.appName === "string" ? payload.appName.trim() : "";
  const appVersion = typeof payload.appVersion === "string" ? payload.appVersion.trim() : "";
  const description = typeof payload.description === "string" ? payload.description.trim() : "";
  const chatApiUrl = typeof payload.chatApiUrl === "string" ? payload.chatApiUrl.trim() : "";
  const supabaseProjectRef = typeof payload.supabaseProjectRef === "string"
    ? payload.supabaseProjectRef.trim()
    : "";
  const apiMasterKey = typeof payload.apiMasterKey === "string" && payload.apiMasterKey.trim().length > 0
    ? payload.apiMasterKey.trim()
    : null;
  const apiRequestTimeout = typeof payload.apiRequestTimeout === "number"
    ? payload.apiRequestTimeout
    : Number(payload.apiRequestTimeout ?? 0);

  if (!appName || !appVersion || !chatApiUrl || !supabaseProjectRef) {
    return jsonResponse({ detail: "请填写完整的必要字段" }, 400);
  }

  if (!Number.isFinite(apiRequestTimeout) || apiRequestTimeout < 10) {
    return jsonResponse({ detail: "请求超时时间至少为 10 秒" }, 400);
  }

  const knownModels = Array.isArray(payload.knownModels)
    ? payload.knownModels.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : parseKnownModels(typeof payload.knownModels === "string" ? payload.knownModels : "");

  const rawTokens = Array.isArray(payload.authTokens)
    ? payload.authTokens.filter((item): item is string => typeof item === "string").map((item) => item.trim())
    : [];

  if (rawTokens.length === 0) {
    return jsonResponse({ detail: "至少需要配置一条 Smithery Token" }, 400);
  }

  const normalizedTokens: string[] = [];
  try {
    for (const value of rawTokens) {
      normalizedTokens.push(normalizeTokenValue(value));
    }
  } catch (error) {
    return jsonResponse({
      detail: error instanceof Error ? error.message : String(error),
    }, 400);
  }

  const current = getRuntimeConfig().stored;
  const updated: StoredConfig = {
    ...current,
    appName,
    appVersion,
    description,
    chatApiUrl,
    apiMasterKey,
    apiRequestTimeout,
    knownModels,
    supabaseProjectRef,
    authTokens: normalizedTokens,
  };

  try {
    await persistConfig(updated);
  } catch (error) {
    console.error("[ERROR] 保存配置失败:", error);
    return jsonResponse({ detail: "保存配置失败，请稍后重试。" }, 500);
  }

  await appendLog(`配置已更新：Token 数量 ${normalizedTokens.length}。`);

  return jsonResponse({ detail: "配置已更新" });
}
async function handlePasswordChange(request: Request): Promise<Response> {
  const { ok } = await isAuthenticated(request);
  if (!ok) {
    return jsonResponse({ detail: "未授权" }, 401);
  }

  let payload: Record<string, unknown>;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ detail: "请求体必须是 JSON" }, 400);
  }

  const currentPassword = typeof payload.currentPassword === "string"
    ? payload.currentPassword
    : "";
  const newPassword = typeof payload.newPassword === "string"
    ? payload.newPassword
    : "";

  if (!currentPassword || !newPassword) {
    return jsonResponse({ detail: "请输入完整的密码信息" }, 400);
  }

  if (newPassword.length < 6) {
    return jsonResponse({ detail: "新密码长度至少为 6 位" }, 400);
  }

  const config = getRuntimeConfig();
  const correct = await verifyPassword(currentPassword, config.stored.adminPasswordHash);
  if (!correct) {
    return jsonResponse({ detail: "当前密码不正确" }, 403);
  }

  const newHash = await hashPassword(newPassword);
  const updated: StoredConfig = {
    ...config.stored,
    adminPasswordHash: newHash,
  };

  await persistConfig(updated);
  await appendLog("管理员更新了后台密码。");

  return jsonResponse({ detail: "密码已更新" });
}

async function handleLogsGet(request: Request): Promise<Response> {
  const { ok } = await isAuthenticated(request);
  if (!ok) {
    return jsonResponse({ detail: "未授权" }, 401);
  }

  const logs = await getLogs();
  return jsonResponse({ logs });
}

async function handleUsageLogsGet(request: Request): Promise<Response> {
  const { ok } = await isAuthenticated(request);
  if (!ok) {
    return jsonResponse({ detail: "未授权" }, 401);
  }

  const logs = await getUsageLogs();
  return jsonResponse({ logs });
}

const port = Number(Deno.env.get("PORT") ?? Deno.env.get("NGINX_PORT") ?? "8088");

console.log(
  `应用启动中... ${runtimeConfig.stored.appName} v${runtimeConfig.stored.appVersion}`,
);
console.log(
  "服务已进入 'Cloudscraper' 模式（模拟），将自动处理 Cloudflare 挑战。",
);
console.log(
  `服务将在 http://localhost:${port} 上可用，已加载 ${runtimeConfig.authCookies.length} 组身份凭据。`,
);
console.log("后台登录默认密码：123456（请尽快修改）。");

Deno.serve({ port }, async (request) => {
  const url = new URL(request.url);

  if (url.pathname === "/v1/chat/completions" && request.method === "POST") {
    return handleChatCompletions(request);
  }

  if (url.pathname === "/v1/models" && request.method === "GET") {
    return handleModels(request);
  }

  if (url.pathname === "/" && request.method === "GET") {
    return handleRoot();
  }

  if (url.pathname === "/admin" && request.method === "GET") {
    return handleAdmin(request);
  }

  if (url.pathname === "/admin/login" && request.method === "POST") {
    return handleLogin(request);
  }

  if (url.pathname === "/admin/logout" && request.method === "POST") {
    return handleLogout(request);
  }

  if (url.pathname === "/admin/api/config") {
    if (request.method === "GET") {
      return handleConfigGet(request);
    }
    if (request.method === "POST") {
      return handleConfigPost(request);
    }
  }

  if (url.pathname === "/admin/api/password" && request.method === "POST") {
    return handlePasswordChange(request);
  }

  if (url.pathname === "/admin/api/logs" && request.method === "GET") {
    return handleLogsGet(request);
  }

  if (url.pathname === "/admin/api/usage" && request.method === "GET") {
    return handleUsageLogsGet(request);
  }

  return jsonResponse({ detail: "未找到对应的路由。" }, 404);
});
