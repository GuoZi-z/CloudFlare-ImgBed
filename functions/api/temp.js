export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const path = url.searchParams.get("path");
  const ttl = parseInt(url.searchParams.get("ttl") || "1800", 10);

  if (!path) {
    return new Response("missing path", { status: 400 });
  }

  const exp = Math.floor(Date.now() / 1000) + ttl;
  const data = `${path}:${exp}`;
  const secret = env.TEMP_LINK_SECRET;

  if (!secret) {
    return new Response("server misconfigured", { status: 500 });
  }

  const sig = await sign(data, secret);
  const host = url.origin;
  const tempLink = `${host}/api/temp/dl?path=${encodeURIComponent(path)}&exp=${exp}&sig=${sig}`;

  return new Response(JSON.stringify({ url: tempLink, expires: exp }), {
    headers: { "Content-Type": "application/json" }
  });
}

async function sign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
