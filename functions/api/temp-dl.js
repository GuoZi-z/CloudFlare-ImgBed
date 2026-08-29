import { getDatabase } from "../utils/databaseAdapter.js";

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const token = url.searchParams.get("token") || "";
  if (!token) return new Response("参数不完整", { status: 400 });

  let path, exp;
  try {
    const bin = atob(token);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
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
    exp = parseInt(parts[1]);
  } catch (e) {
    return new Response("链接无效", { status: 403 });
  }

  if (Math.floor(Date.now() / 1000) > exp) {
    return new Response("链接已过期", { status: 403 });
  }

  const db = getDatabase(env);

  const row = await db.getWithMetadata(path);
  if (!row || row.value === null) {
    return new Response("文件不存在", { status: 404 });
  }
  const meta = row.metadata || {};
  const channel = meta.Channel || "";

  let dlResp;
  try {
    if (channel === "TelegramNew") {
      const proxy = meta.TgProxyUrl || "api.telegram.org";
      const gf = await fetch(`https://${proxy}/bot${meta.TgBotToken}/getFile?file_id=${meta.TgFileId}`);
      if (!gf.ok) return new Response("获取文件失败", { status: 502 });
      const gj = await gf.json();
      if (!gj.ok) return new Response("获取文件失败", { status: 502 });
      dlResp = await fetch(`https://${proxy}/file/bot${meta.TgBotToken}/${gj.result.file_path}`, {
        headers: { Range: request.headers.get("Range") || "" }
      });

    } else if (channel === "CloudflareR2" || channel === "R2" || channel === "cfr2") {
      if (!env.R2_BUCKET) return new Response("存储未配置", { status: 500 });
      const obj = await env.R2_BUCKET.get(path, {
        range: request.headers.get("Range") ? parseRange(request.headers.get("Range")) : undefined
      });
      if (!obj) return new Response("文件不存在", { status: 404 });
      dlResp = new Response(obj.body, {
        status: 200,
        headers: { "Content-Type": obj.httpMetadata?.contentType || "application/octet-stream", "Cache-Control": "no-store" }
      });

    } else if (channel === "HuggingFace" || channel === "huggingface") {
      const token = meta.HfToken;
      const repo = meta.HfRepo;
      const hfPath = meta.HfPath || path;
      const rev = meta.HfRevision || "main";
      const proxy = meta.HfProxyUrl || "huggingface.co";
      const hfUrl = `https://${proxy}/${repo.replace("/", "/resolve/")}/${encodeURIComponent(hfPath).replace("%2F", "/")}?revision=${rev}`;
      dlResp = await fetch(hfUrl, {
        headers: { Range: request.headers.get("Range") || "", ...(token ? { Authorization: `Bearer ${token}` } : {}) }
      });
      if (!dlResp.ok) return new Response("获取文件失败", { status: 502 });

    } else if (channel === "Discord" || channel === "discord") {
      const proxy = meta.DiscordProxyUrl || "discord.com";
      let attachUrl = meta.AttachmentUrl;
      if (!attachUrl) {
        const mResp = await fetch(`https://${proxy}/api/v10/channels/${meta.DiscordChannelId}/messages/${meta.DiscordMessageId}`, {
          headers: { Authorization: `Bot ${meta.DiscordToken}` }
        });
        if (!mResp.ok) return new Response("获取文件失败", { status: 502 });
        const mJson = await mResp.json();
        const att = (mJson.attachments || []).find(a => a.id === meta.DiscordAttachmentId) || mJson.attachments?.[0];
        if (!att) return new Response("文件不存在", { status: 404 });
        attachUrl = att.url;
      }
      dlResp = await fetch(attachUrl, { headers: { Range: request.headers.get("Range") || "" } });
      if (!dlResp.ok) return new Response("获取文件失败", { status: 502 });

    } else {
      if (row.value) {
        dlResp = new Response(row.value, { status: 200, headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" } });
      } else {
        return new Response("不支持的存储渠道", { status: 400 });
      }
    }
  } catch (e) {
    return new Response("服务异常", { status: 500 });
  }

  if (!dlResp || !dlResp.ok) return new Response("下载失败", { status: 502 });

  return new Response(dlResp.body, {
    status: dlResp.status,
    headers: {
      "Content-Type": dlResp.headers.get("Content-Type") || "application/octet-stream",
      "Cache-Control": "no-store",
      "Content-Disposition": `attachment; filename="${path.split("/").pop()}"`,
      ...(dlResp.headers.get("Content-Range") ? { "Content-Range": dlResp.headers.get("Content-Range") } : {}),
      ...(dlResp.headers.get("Accept-Ranges") ? { "Accept-Ranges": dlResp.headers.get("Accept-Ranges") } : {})
    }
  });
}

function parseRange(r) {
  const m = r.match(/bytes=(\d*)-(\d*)/);
  if (!m) return undefined;
  const s = m[1] ? parseInt(m[1], 10) : undefined;
  const e = m[2] ? parseInt(m[2], 10) : undefined;
  if (s !== undefined && e !== undefined) return { offset: s, length: e - s + 1 };
  if (s !== undefined) return { offset: s };
  return undefined;
}
