import { getDatabase } from "../utils/databaseAdapter.js";

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const path = url.searchParams.get("path");
  const ttl = parseInt(url.searchParams.get("ttl") || "1800", 10);
  const expires = parseInt(url.searchParams.get("expires") || "0");
  const signature = url.searchParams.get("signature") || "";
  const userId = url.searchParams.get("userId") || "";

  if (!path) {
    return new Response("missing path", { status: 400 });
  }

  // 签名验证
  if (!signature || !expires) {
    return new Response(JSON.stringify({ error: "参数不完整" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const now = Math.floor(Date.now() / 1000);
  if (expires < now) {
    return new Response(JSON.stringify({ error: "签名已过期" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  if (!env.UPLOAD_SECRET) {
    return new Response(JSON.stringify({ error: "服务未配置" }), { status: 500, headers: { "Content-Type": "application/json" } });
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(path + ttl + expires + userId);
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.UPLOAD_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuffer = await crypto.subtle.sign("HMAC", key, data);
  const expectedSig = [...new Uint8Array(sigBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
  if (signature !== expectedSig) {
    return new Response(JSON.stringify({ error: "签名无效" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }

  // 生成临时链接（不暴露 path）
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const nonce = generateNonce();

  // 把 path 存到 KV，用 nonce 当 key
  const db = getDatabase(env);
  await db.put(`temp_path:${nonce}`, path, { expirationTtl: ttl });

  // 签名：nonce:exp
  const linkData = `${nonce}:${exp}`;
  const sig = await sign(linkData, env.TEMP_LINK_SECRET);

  const tempLink = `${url.origin}/api/temp-dl?nonce=${nonce}&exp=${exp}&sig=${sig}`;

  return new Response(JSON.stringify({ url: tempLink, expires: exp }), {
    headers: { "Content-Type": "application/json" }
  });
}

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return [...arr].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
