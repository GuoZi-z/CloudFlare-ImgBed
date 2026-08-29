import { userAuthCheck, UnauthorizedResponse } from "../../utils/userAuth";

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // 1. userAuthCheck 鉴权
  if (!await userAuthCheck(env, url, request, 'manage')) {
    return UnauthorizedResponse('Unauthorized');
  }

  // 2. 参数
  const path = url.searchParams.get("path");
  const ttl = parseInt(url.searchParams.get("ttl") || "1800", 10);
  const expires = parseInt(url.searchParams.get("expires") || "0");
  const signature = url.searchParams.get("signature") || "";
  const userId = url.searchParams.get("userId") || "";

  if (!path) {
    return new Response("missing path", { status: 400 });
  }

  // 3. 签名验证（用 UPLOAD_SECRET）
  const sigCheck = await verifySignature(path, ttl, expires, signature, userId, env.UPLOAD_SECRET);
  if (!sigCheck.valid) {
    return new Response(JSON.stringify({ error: sigCheck.message }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  // 4. 生成临时下载链接
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const nonce = generateNonce();
  const data = `${path}:${exp}:${nonce}`;
  const sig = await sign(data, env.TEMP_LINK_SECRET);

  const tempLink = `${url.origin}/api/temp/dl?path=${encodeURIComponent(path)}&exp=${exp}&nonce=${nonce}&sig=${sig}`;

  return new Response(JSON.stringify({ url: tempLink, expires: exp }), {
    headers: { "Content-Type": "application/json" }
  });
}

async function verifySignature(path, ttl, expires, signature, userId, secret) {
  if (!signature || !expires) {
    return { valid: false, message: "missing signature params" };
  }
  const now = Math.floor(Date.now() / 1000);
  if (expires < now) {
    return { valid: false, message: "signature expired" };
  }
  if (!secret) {
    return { valid: false, message: "server misconfigured" };
  }
  const encoder = new TextEncoder();
  const data = encoder.encode(path + ttl + expires + userId);
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuffer = await crypto.subtle.sign("HMAC", key, data);
  const expectedSig = [...new Uint8Array(sigBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
  if (signature !== expectedSig) {
    return { valid: false, message: "invalid signature" };
  }
  return { valid: true };
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
