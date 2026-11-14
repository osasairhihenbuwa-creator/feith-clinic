
const encoder = new TextEncoder();

function respond(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Vary": "Origin",
  };
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  return new Response(JSON.stringify(data), { status, headers });
}

function getOrigin(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return "";
  const allowed = (env.ALLOWED_ORIGIN || "")
    .split(",").map(x => x.trim());
  return allowed.includes(origin) ? origin : "";
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(x => x.toString(16).padStart(2, "0")).join("");
}

function toBase64Url(bytes) {
  let str = "";
  for (const byte of bytes) str += String.fromCharCode(byte);
  return btoa(str).replace(/\+/g, "-")
    .replace(/\//g, "_").replace(/=+$/, "");
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2",
    false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: encoder.encode(salt),
    iterations: 210000,
    hash: "SHA-256"
  }, key, 256);
  return toHex(bits);
}

function newSalt() {
  return toHex(crypto.getRandomValues(new Uint8Array(16)));
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function signToken(member, secret) {
  const header = toBase64Url(
    encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  );
  const now = Math.floor(Date.now() / 1000);
  const payload = toBase64Url(encoder.encode(JSON.stringify({
    sub: String(member.id),
    role: member.role,
    iat: now,
    exp: now + 3600
  })));
  const input = header + "." + payload;
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC", key, encoder.encode(input)
  );
  return input + "." + toBase64Url(new Uint8Array(signature));
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false, ["verify"]
    );
    const base64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
    const signature = Uint8Array.from(
      atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")),
      c => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify(
      "HMAC", key, signature,
      encoder.encode(parts[0] + "." + parts[1])
    );
    if (!valid) return null;
    const header = JSON.parse(atob(
      parts[0].replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(parts[0].length / 4) * 4, "=")
    ));
    if (header.alg !== "HS256") return null;
    const payload = JSON.parse(atob(
      parts[1].replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(parts[1].length / 4) * 4, "=")
    ));
    if (!Number.isInteger(payload.exp) ||
        payload.exp <= Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

async function readBody(request) {
  const type = request.headers.get("Content-Type") || "";
  if (!type.toLowerCase().includes("application/json")) {
    throw new Error("JSON content required");
  }
  if (Number(request.headers.get("Content-Length")) > 16384) {
    throw new Error("Request too large");
  }
  const text = await request.text();
  if (text.length > 16384) throw new Error("Request too large");
  const body = JSON.parse(text);
  if (!body || Array.isArray(body) || typeof body !== "object") {
    throw new Error("Invalid JSON object");
  }
  return body;
}

async function authenticate(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const payload = await verifyToken(auth.slice(7), env.JWT_SECRET);
  if (!payload) return null;
  const member = await env.DB.prepare(
    "SELECT id, name, email, role FROM members WHERE id = ?"
  ).bind(payload.sub).first();
  if (!member || member.role !== payload.role) return null;
  return member;
}

export default {
  async fetch(request, env) {
    const origin = getOrigin(request, env);
    const incomingOrigin = request.headers.get("Origin");
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      if (incomingOrigin && !origin) {
        return respond({ error: "Origin not allowed" }, 403);
      }
      return new Response(null, {
        status: 204,
        headers: {
          ...(origin ? { "Access-Control-Allow-Origin": origin } : {}),
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Vary": "Origin",
          "Access-Control-Max-Age": "600"
        }
      });
    }

    if (incomingOrigin && !origin) {
      return respond({ error: "Origin not allowed" }, 403);
    }

    if (path === "/api/health" && request.method === "GET") {
      return respond({
        status: "running",
        service: "FAITH CLINIC Membership API",
        database: Boolean(env.DB),
        authenticationConfigured: Boolean(env.JWT_SECRET)
      }, 200, origin);
    }

    if (!path.startsWith("/api/")) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return respond({ service: "FAITH CLINIC API" }, 200, origin);
    }

    if (!env.DB || !env.JWT_SECRET) {
      return respond({ error: "Service configuration incomplete" }, 503, origin);
    }

    try {
      if (path === "/api/register" && request.method === "POST") {
        const body = await readBody(request);
        const name = typeof body.name === "string" ? body.name.trim() : "";
        const email = typeof body.email === "string"
          ? body.email.trim().toLowerCase() : "";
        const password = body.password;

        if (name.length < 2 || name.length > 100 ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            typeof password !== "string" ||
            password.length < 8 || password.length > 1024) {
          return respond({ error: "Invalid name, email or password (minimum 8 characters)" }, 400, origin);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM members WHERE email = ?"
        ).bind(email).first();

        if (existing) {
          return respond({ error: "Email already registered" }, 409, origin);
        }

        const salt = newSalt();
        const passwordHash = await hashPassword(password, salt);
        const id = crypto.randomUUID();

        await env.DB.prepare(
          `INSERT INTO members
           (id, name, email, password_hash, salt, role, created_at)
           VALUES (?, ?, ?, ?, ?, 'member', ?)`
        ).bind(
          id, name, email, passwordHash, salt,
          new Date().toISOString()
        ).run();

        return respond({
          success: true,
          message: "Registration successful"
        }, 201, origin);
      }

      if ((path === "/api/login" ||
           path === "/api/admin/login") &&
           request.method === "POST") {
        const body = await readBody(request);
        const email = typeof body.email === "string"
          ? body.email.trim().toLowerCase() : "";
        const password = body.password;

        if (!email || typeof password !== "string") {
          return respond({ error: "Invalid credentials" }, 401, origin);
        }

        const member = await env.DB.prepare(
          `SELECT id, name, email, password_hash, salt, role
           FROM members WHERE email = ?`
        ).bind(email).first();

        if (!member) {
          return respond({ error: "Invalid credentials" }, 401, origin);
        }

        const candidate = await hashPassword(password, member.salt);
        if (!safeEqual(candidate, member.password_hash)) {
          return respond({ error: "Invalid credentials" }, 401, origin);
        }

        if (path === "/api/admin/login" && member.role !== "admin") {
          return respond({ error: "Administrator access required" }, 403, origin);
        }

        const token = await signToken(member, env.JWT_SECRET);
        return respond({
          success: true,
          token,
          token_type: "Bearer",
          expires_in: 3600,
          member: {
            id: member.id,
            name: member.name,
            email: member.email,
            role: member.role
          }
        }, 200, origin);
      }

      if (path === "/api/me" && request.method === "GET") {
        const member = await authenticate(request, env);
        if (!member) return respond({ error: "Unauthorized" }, 401, origin);
        return respond({ member }, 200, origin);
      }

      if (path === "/api/members" && request.method === "GET") {
        const member = await authenticate(request, env);
        if (!member || member.role !== "admin") {
          return respond({ error: "Forbidden" }, 403, origin);
        }
        const results = await env.DB.prepare(
          `SELECT id, name, email, role, created_at
           FROM members ORDER BY created_at DESC LIMIT 100`
        ).all();
        return respond({ members: results.results }, 200, origin);
      }

      return respond({ error: "API endpoint not found" }, 404, origin);
    } catch (error) {
      console.error("FAITH CLINIC API error:", error);
      if (error instanceof SyntaxError ||
          ["JSON content required", "Request too large",
           "Invalid JSON object"].includes(error.message)) {
        return respond({ error: "Invalid request body" }, 400, origin);
      }
      return respond({
        error: "Server error. Check Worker logs and database schema."
      }, 500, origin);
    }
  }
};
