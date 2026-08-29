import { getDatabase } from "../utils/databaseAdapter.js";

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // 修复 Base64 URL 中 '+' 被解析为空格的常见问题
  let token = url.searchParams.get("token") || "";
  token = token.replace(/ /g, '+');
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
    return errorResponse("链接无效", 403);
  }

  if (Math.floor(Date.now() / 1000) > exp) {
    return errorResponse("链接已过期", 403);
  }

  // 安全地处理路径，防止目录遍历
  path = sanitizePath(path);
  if (!path) return errorResponse("非法路径", 403);

  const db = getDatabase(env);
  const row = await db.getWithMetadata(path);
  if (!row || row.value === null) {
    return errorResponse("文件不存在", 404);
  }

  const meta = row.metadata || {};
  const channel = meta.Channel || "";

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
      case "HuggingFace":
      case "huggingface":
        dlResp = await handleHuggingFace(meta, path, request);
        break;
      case "Discord":
      case "discord":
        dlResp = await handleDiscord(meta, request);
        break;
      default:
        dlResp = await handleDirect(row, request);
        break;
    }
  } catch (e) {
    console.error("Download error:", e);
    return errorResponse("服务异常", 500);
  }

  if (!dlResp || !dlResp.ok) {
    return errorResponse("下载失败", 502);
  }

  // 构建响应头，添加 CORS 支持
  const headers = {
    "Content-Type": dlResp.headers.get("Content-Type") || "application/octet-stream",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD",
  };

  // 安全地设置 Content-Disposition
  const filename = path.split("/").pop() || "download";
  const safeFilename = encodeURIComponent(filename).replace(/'/g, "%27");
  headers["Content-Disposition"] = `attachment; filename*=UTF-8''${safeFilename}`;

  // 转发 Range 相关头
  if (dlResp.headers.get("Content-Range")) {
    headers["Content-Range"] = dlResp.headers.get("Content-Range");
  }
  if (dlResp.headers.get("Accept-Ranges")) {
    headers["Accept-Ranges"] = dlResp.headers.get("Accept-Ranges");
  }

  return new Response(dlResp.body, {
    status: dlResp.status,
    headers,
  });
}

// ========== 辅助函数 ==========

function errorResponse(message, status) {
  return new Response(message, { status, headers: { "Content-Type": "text/plain;charset=UTF-8" } });
}

function sanitizePath(path) {
  // 移除 .. 和多余的斜杠，防止目录遍历
  const normalized = path.replace(/\.\./g, "").replace(/\/+/g, "/");
  // 根据业务需要，可限制必须以某个前缀开头
  // if (!normalized.startsWith("gba/rom/")) return null;
  return normalized;
}

// ---------- Telegram 渠道 ----------
async function handleTelegram(meta, request) {
  const proxy = meta.TgProxyUrl || "api.telegram.org";
  // 确保 proxy 不含协议前缀
  const cleanProxy = proxy.replace(/^https?:\/\//, "");
  const baseUrl = `https://${cleanProxy}`;

  const gf = await fetch(`${baseUrl}/bot${meta.TgBotToken}/getFile?file_id=${meta.TgFileId}`);
  if (!gf.ok) throw new Error("Telegram getFile failed");
  const gj = await gf.json();
  if (!gj.ok) throw new Error("Telegram getFile response error");

  const fileUrl = `${baseUrl}/file/bot${meta.TgBotToken}/${gj.result.file_path}`;
  return fetch(fileUrl, {
    headers: { Range: request.headers.get("Range") || "" },
  });
}

// ---------- Cloudflare R2 渠道 ----------
async function handleR2(env, path, request) {
  if (!env.R2_BUCKET) throw new Error("R2 bucket not configured");

  const rangeHeader = request.headers.get("Range");
  let rangeOptions = undefined;
  if (rangeHeader) {
    const parsed = parseRange(rangeHeader);
    if (parsed) {
      // 仅支持单段 range
      if (parsed.offset !== undefined && parsed.length !== undefined) {
        rangeOptions = { offset: parsed.offset, length: parsed.length };
      } else if (parsed.offset !== undefined) {
        rangeOptions = { offset: parsed.offset };
      }
    }
  }

  const obj = await env.R2_BUCKET.get(path, { range: rangeOptions });
  if (!obj) throw new Error("Object not found");

  const headers = {
    "Content-Type": obj.httpMetadata?.contentType || "application/octet-stream",
    "Cache-Control": "no-store",
  };
  // 如果对象支持 range，添加 Accept-Ranges
  if (obj.range) {
    headers["Accept-Ranges"] = "bytes";
    if (obj.range.offset !== undefined && obj.range.length !== undefined) {
      const end = obj.range.offset + obj.range.length - 1;
      const total = obj.size || 0;
      headers["Content-Range"] = `bytes ${obj.range.offset}-${end}/${total}`;
    }
  }
  return new Response(obj.body, { status: 200, headers });
}

// ---------- HuggingFace 渠道（修复） ----------
async function handleHuggingFace(meta, path, request) {
  const token = meta.HfToken;
  const repo = meta.HfRepo;          // 格式 "username/repo"
  const hfPath = meta.HfPath || path;
  const rev = meta.HfRevision || "main";
  const proxy = meta.HfProxyUrl || "huggingface.co";
  const cleanProxy = proxy.replace(/^https?:\/\//, "");

  // 构建正确的 URL：https://{proxy}/{repo}/resolve/{rev}/{path}
  // 将路径分段编码，保留斜杠
  const encodedPath = hfPath.split("/").map(encodeURIComponent).join("/");
  const hfUrl = `https://${cleanProxy}/${repo}/resolve/${rev}/${encodedPath}`;

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
  const proxy = meta.DiscordProxyUrl || "discord.com";
  const cleanProxy = proxy.replace(/^https?:\/\//, "");
  const baseUrl = `https://${cleanProxy}`;

  let attachUrl = meta.AttachmentUrl;
  if (!attachUrl) {
    // 需要从消息中获取附件
    const msgUrl = `${baseUrl}/api/v10/channels/${meta.DiscordChannelId}/messages/${meta.DiscordMessageId}`;
    const resp = await fetch(msgUrl, {
      headers: { Authorization: `Bot ${meta.DiscordToken}` }
    });
    if (!resp.ok) throw new Error(`Discord message fetch failed: ${resp.status}`);
    const msg = await resp.json();

    // 根据附件 ID 精确查找，若无则取第一个
    const attachments = msg.attachments || [];
    let att = null;
    if (meta.DiscordAttachmentId) {
      att = attachments.find(a => a.id === meta.DiscordAttachmentId);
    }
    if (!att && attachments.length > 0) {
      att = attachments[0];
    }
    if (!att) throw new Error("No attachment found");
    attachUrl = att.url;
  }

  return fetch(attachUrl, {
    headers: { Range: request.headers.get("Range") || "" },
  });
}

// ---------- 直接存储（内存/KV） ----------
async function handleDirect(row, request) {
  if (!row.value) throw new Error("No data");
  // 如果 value 是字符串或 Buffer，直接返回，但注意内存占用
  return new Response(row.value, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" },
  });
}

// ---------- Range 解析（支持 bytes=start-end 和 bytes=start-） ----------
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
  // 仅 end 的情况（bytes=-suffix）未实现，可忽略或返回全部
  return null;
}