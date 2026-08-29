import { getDatabase } from "../utils/databaseAdapter.js";

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // ---------- Token 解析 ----------
  let token = url.searchParams.get("token") || "";
  token = token.replace(/ /g, '+'); // 修复 URL 中 '+' 被解析为空格
  if (!token) return errorResponse("参数不完整", 400);

  let path, exp;
  try {
    const bin = atob(token);
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    const iv = bytes.slice(0, 16);
    const encrypted = bytes.slice(16);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.TEMP_LINK_SECRET),
      { name: "AES-CBC" },
      false,
      ["decrypt"]
    );
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, encrypted);
    const decoded = new TextDecoder().decode(plainBuf);
    const parts = decoded.split("|");
    path = parts[0];
    exp = parseInt(parts[1], 10);
  } catch (e) {
    console.error("Decrypt error:", e);
    return errorResponse("链接无效", 403);
  }

  if (Math.floor(Date.now() / 1000) > exp) {
    return errorResponse("链接已过期", 403);
  }

  // 安全路径
  path = sanitizePath(path);
  if (!path) return errorResponse("非法路径", 403);

  // ---------- 获取文件元数据 ----------
  const db = getDatabase(env);
  const row = await db.getWithMetadata(path);
  if (!row || row.value === null) {
    return errorResponse("文件不存在", 404);
  }

  const meta = row.metadata || {};
  const channel = meta.Channel || "";

  // ---------- 按渠道分发 ----------
  let dlResp;
  try {
    switch (channel) {
      case "TelegramNew":
        dlResp = await handleTelegram(meta, request);
        break;
      case "CloudflareR2":
      case "R2":
      case "cfr2":
        dlResp = await handleR2(env, path, request);
        break;
      case "S3":
        dlResp = await handleS3(meta, path, request);
        break;
      case "HuggingFace":
      case "huggingface":
        dlResp = await handleHuggingFace(meta, path, request);
        break;
      case "Discord":
      case "discord":
        dlResp = await handleDiscord(meta, request);
        break;
      case "External":
        dlResp = await handleExternal(meta);
        break;
      case "Telegraph":
        dlResp = await handleTelegraph(meta, request);
        break;
      default:
        // 直接存储（内存/KV）
        dlResp = await handleDirect(row, request);
        break;
    }
  } catch (e) {
    console.error("Download error:", e);
    return errorResponse("服务异常: " + e.message, 500);
  }

  if (!dlResp || !dlResp.ok) {
    return errorResponse("下载失败", 502);
  }

  // ---------- 构建响应 ----------
  const headers = {
    "Content-Type": dlResp.headers.get("Content-Type") || "application/octet-stream",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD",
  };

  // 安全文件名
  const filename = path.split("/").pop() || "download";
  const safeFilename = encodeURIComponent(filename).replace(/'/g, "%27");
  headers["Content-Disposition"] = `attachment; filename*=UTF-8''${safeFilename}`;

  // 转发 Range 头
  if (dlResp.headers.get("Content-Range")) {
    headers["Content-Range"] = dlResp.headers.get("Content-Range");
  }
  if (dlResp.headers.get("Accept-Ranges")) {
    headers["Accept-Ranges"] = dlResp.headers.get("Accept-Ranges");
  }

  return new Response(dlResp.body, { status: dlResp.status, headers });
}

// ===================== 辅助函数 =====================

function errorResponse(message, status) {
  return new Response(message, { status, headers: { "Content-Type": "text/plain;charset=UTF-8" } });
}

function sanitizePath(path) {
  if (!path || typeof path !== "string") return null;
  // 移除 .. 和多余斜杠
  let cleaned = path.replace(/\.\./g, "").replace(/\/+/g, "/");
  // 可限制前缀，根据需要开启
  // if (!cleaned.startsWith("gba/rom/")) return null;
  return cleaned || null;
}

// ---------- Telegram 渠道 ----------
async function handleTelegram(meta, request) {
  if (!meta.TgBotToken || !meta.TgFileId) {
    throw new Error("Missing Telegram credentials (TgBotToken or TgFileId)");
  }
  const proxy = (meta.TgProxyUrl || "api.telegram.org").replace(/^https?:\/\//, "");
  const baseUrl = `https://${proxy}`;

  // 获取 file_path
  const gf = await fetch(`${baseUrl}/bot${meta.TgBotToken}/getFile?file_id=${meta.TgFileId}`);
  if (!gf.ok) throw new Error(`Telegram getFile failed: ${gf.status}`);
  const gj = await gf.json();
  if (!gj.ok) throw new Error(`Telegram getFile error: ${gj.description || "unknown"}`);

  const fileUrl = `${baseUrl}/file/bot${meta.TgBotToken}/${gj.result.file_path}`;
  return fetch(fileUrl, { headers: { Range: request.headers.get("Range") || "" } });
}

// ---------- Cloudflare R2 渠道 ----------
async function handleR2(env, path, request) {
  if (!env.R2_BUCKET) throw new Error("R2 bucket not configured");
  const rangeHeader = request.headers.get("Range");
  let rangeOptions = undefined;
  if (rangeHeader) {
    const parsed = parseRange(rangeHeader);
    if (parsed) {
      rangeOptions = parsed.offset !== undefined ? { offset: parsed.offset } : undefined;
      if (parsed.length !== undefined && rangeOptions) {
        rangeOptions.length = parsed.length;
      }
    }
  }
  const obj = await env.R2_BUCKET.get(path, { range: rangeOptions });
  if (!obj) throw new Error("R2 object not found");

  const headers = {
    "Content-Type": obj.httpMetadata?.contentType || "application/octet-stream",
    "Cache-Control": "no-store",
  };
  if (obj.range) {
    headers["Accept-Ranges"] = "bytes";
    if (obj.range.offset !== undefined && obj.range.length !== undefined) {
      const end = obj.range.offset + obj.range.length - 1;
      headers["Content-Range"] = `bytes ${obj.range.offset}-${end}/${obj.size || 0}`;
    }
  }
  return new Response(obj.body, { status: 200, headers });
}

// ---------- S3 兼容存储（如 MinIO、AWS S3） ----------
async function handleS3(meta, path, request) {
  // 这里需要使用 AWS SDK 或直接构建签名 URL，示例用 fetch 简单处理
  // 实际项目中可引入 @aws-sdk/client-s3
  // 如果 meta 中有预签名 URL 可直接使用
  const endpoint = meta.S3Endpoint || "https://s3.amazonaws.com";
  const bucket = meta.S3Bucket;
  const region = meta.S3Region || "us-east-1";
  const accessKey = meta.S3AccessKey;
  const secretKey = meta.S3SecretKey;
  if (!bucket) throw new Error("Missing S3 bucket");
  // 简单实现：使用预签名 URL（需要自行生成，或直接使用 meta.S3SignedUrl）
  if (meta.S3SignedUrl) {
    const resp = await fetch(meta.S3SignedUrl, { headers: { Range: request.headers.get("Range") || "" } });
    if (!resp.ok) throw new Error(`S3 signed URL fetch failed: ${resp.status}`);
    return resp;
  }
  throw new Error("S3 signed URL not provided");
}

// ---------- HuggingFace 渠道（修复 URL 构建） ----------
async function handleHuggingFace(meta, path, request) {
  if (!meta.HfRepo) throw new Error("Missing HuggingFace repo");
  const token = meta.HfToken;
  const repo = meta.HfRepo;          // "username/repo"
  const hfPath = meta.HfPath || path;
  const rev = meta.HfRevision || "main";
  const proxy = (meta.HfProxyUrl || "huggingface.co").replace(/^https?:\/\//, "");

  // 分段编码路径，保留斜杠
  const encodedPath = hfPath.split("/").map(encodeURIComponent).join("/");
  const hfUrl = `https://${proxy}/${repo}/resolve/${rev}/${encodedPath}`;

  const headers = {
    "Range": request.headers.get("Range") || "",
    ...(token ? { "Authorization": `Bearer ${token}` } : {}),
  };
  const resp = await fetch(hfUrl, { headers });
  if (!resp.ok) throw new Error(`HuggingFace fetch failed: ${resp.status}`);
  return resp;
}

// ---------- Discord 渠道 ----------
async function handleDiscord(meta, request) {
  if (!meta.DiscordToken || !meta.DiscordChannelId || !meta.DiscordMessageId) {
    throw new Error("Missing Discord credentials (Token, ChannelId, MessageId)");
  }
  const proxy = (meta.DiscordProxyUrl || "discord.com").replace(/^https?:\/\//, "");
  const baseUrl = `https://${proxy}`;

  let attachUrl = meta.AttachmentUrl;
  if (!attachUrl) {
    const msgUrl = `${baseUrl}/api/v10/channels/${meta.DiscordChannelId}/messages/${meta.DiscordMessageId}`;
    const resp = await fetch(msgUrl, {
      headers: { Authorization: `Bot ${meta.DiscordToken}` }
    });
    if (!resp.ok) throw new Error(`Discord message fetch failed: ${resp.status}`);
    const msg = await resp.json();
    const attachments = msg.attachments || [];
    let att = null;
    if (meta.DiscordAttachmentId) {
      att = attachments.find(a => a.id === meta.DiscordAttachmentId);
    }
    if (!att && attachments.length > 0) {
      att = attachments[0];
    }
    if (!att) throw new Error("No attachment found in Discord message");
    attachUrl = att.url;
  }
  return fetch(attachUrl, { headers: { Range: request.headers.get("Range") || "" } });
}

// ---------- External（302 重定向） ----------
async function handleExternal(meta) {
  if (!meta.ExternalUrl) throw new Error("Missing ExternalUrl");
  // 直接返回 302 响应，浏览器会跳转
  return new Response(null, {
    status: 302,
    headers: { Location: meta.ExternalUrl },
  });
}

// ---------- Telegraph 渠道 ----------
async function handleTelegraph(meta, request) {
  if (!meta.TelegraphUrl) throw new Error("Missing TelegraphUrl");
  const resp = await fetch(meta.TelegraphUrl, {
    headers: { Range: request.headers.get("Range") || "" },
  });
  if (!resp.ok) throw new Error(`Telegraph fetch failed: ${resp.status}`);
  return resp;
}

// ---------- 直接存储（内存/KV） ----------
async function handleDirect(row, request) {
  if (!row.value) throw new Error("No data in direct storage");
  return new Response(row.value, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" },
  });
}

// ---------- Range 解析 ----------
function parseRange(r) {
  const m = r.match(/bytes=(\d*)-(\d*)/);
  if (!m) return null;
  const start = m[1] !== "" ? parseInt(m[1], 10) : undefined;
  const end = m[2] !== "" ? parseInt(m[2], 10) : undefined;
  if (start === undefined && end === undefined) return null;
  if (start !== undefined && end !== undefined) {
    if (start > end) return null;
    return { offset: start, length: end - start + 1 };
  }
  if (start !== undefined) return { offset: start };
  return null; // bytes=-suffix 暂不支持
}