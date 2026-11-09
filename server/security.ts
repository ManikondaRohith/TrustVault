/** Cryptography, input policy, file validation, rate limiting and lockouts. */
import { createHash, createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { eq, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { appSecrets, lockouts, rateLimits } from "../db/schema.js";
import { HttpError, type Ctx } from "./http.js";

export const SETTINGS = {
  sessionMinutes: 15,
  otpTtlSeconds: 300,
  otpMaxAttempts: 5,
  lockoutThreshold: 5,
  lockoutMinutes: 15,
  // Netlify Functions accept request bodies up to 6 MB, so uploads are capped at 4 MiB.
  maxUploadBytes: 4 * 1024 * 1024,
  rateSignupPer10Min: 10,
  rateLoginPerMin: 30,
};

// ---------------------------------------------------------------------------
// Server secrets: taken from the environment when set, otherwise generated once and kept in the database
// ---------------------------------------------------------------------------
const secretCache = new Map<string, string>();
export async function secret(name: "JWT_SECRET" | "OTP_PEPPER" | "PASSCODE_PEPPER"): Promise<string> {
  const env = process.env[name];
  if (env && env.length >= 32) return env;
  const hit = secretCache.get(name);
  if (hit) return hit;
  await db.insert(appSecrets).values({ name, value: randomBytes(48).toString("base64url") }).onConflictDoNothing();
  const [row] = await db.select().from(appSecrets).where(eq(appSecrets.name, name));
  secretCache.set(name, row.value);
  return row.value;
}

// ---------------------------------------------------------------------------
// Passwords: scrypt (N=2^15, r=8, p=1, 32 MiB) with a fresh random salt per hash
// ---------------------------------------------------------------------------
const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, opts: object) => Promise<Buffer>;
const N = 32768, R = 8, P = 1, KEYLEN = 32;
const SCRYPT_OPTS = { N, r: R, p: P, maxmem: 64 * 1024 * 1024 };

export const PASSWORD_RULES = "At least 12 characters, with an uppercase letter, a lowercase letter, " +
  "a number and a symbol, and not containing your username.";

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize("NFKC"), salt, KEYLEN, SCRYPT_OPTS);
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64")}$${key.toString("base64")}`;
}

let dummyHash: Promise<string> | null = null;
export async function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean> {
  // Unknown usernames take the same time as wrong passwords.
  const h = stored || await (dummyHash ??= hashPassword(randomBytes(18).toString("base64url")));
  const parts = h.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, salt, key] = parts;
  const expected = Buffer.from(key, "base64");
  const got = await scrypt(password.normalize("NFKC"), Buffer.from(salt, "base64"), expected.length,
    { N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 });
  return timingSafeEqual(got, expected) && !!stored;
}

export function passwordProblem(password: string, username = ""): string | null {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) return PASSWORD_RULES;
  if (![/[A-Z]/, /[a-z]/, /\d/, /[^A-Za-z0-9]/].every(re => re.test(password))) return PASSWORD_RULES;
  if (username && password.toLowerCase().includes(username.toLowerCase())) return PASSWORD_RULES;
  return null;
}

// Document passcodes use scrypt too, with a server-side pepper mixed in first.
export async function hashPasscode(passcode: string) { return hashPassword((await secret("PASSCODE_PEPPER")) + passcode); }
export async function verifyPasscode(passcode: string, stored: string) {
  return verifyPassword((await secret("PASSCODE_PEPPER")) + passcode, stored);
}

// ---------------------------------------------------------------------------
// Usernames, emails, names
// ---------------------------------------------------------------------------
export const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_]{2,31}$/;
export const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/;

export function maskEmail(e: string): string {
  const i = e.indexOf("@");
  return i >= 0 ? e.slice(0, Math.min(2, i)) + "•••@" + e.slice(i + 1) : "•••";
}

export function cleanFilename(name: string): string {
  let n = (name || "").replace(/^.*[\\/]/, "");
  n = n.replace(/[^\p{L}\p{N}_. -]/gu, "_").replace(/^[ .]+|[ .]+$/g, "");
  return n.slice(-80);
}

// ---------------------------------------------------------------------------
// JWT session tokens (HS256), delivered only as an HttpOnly cookie
// ---------------------------------------------------------------------------
export const COOKIE_NAME = "tv_session";
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

export async function issueToken(userId: number, tokenVersion: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64u(JSON.stringify({
    sub: String(userId), ver: tokenVersion, iat: now, exp: now + SETTINGS.sessionMinutes * 60,
    jti: randomBytes(8).toString("hex"), iss: "trustvault",
  }));
  const sig = createHmac("sha256", await secret("JWT_SECRET")).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${sig}`;
}

export async function decodeToken(token: string): Promise<{ sub: string; ver: number; iat: number; exp: number } | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const expect = createHmac("sha256", await secret("JWT_SECRET")).update(`${h}.${p}`).digest();
  const got = Buffer.from(s, "base64url");
  if (got.length !== expect.length || !timingSafeEqual(got, expect)) return null;
  try {
    const head = JSON.parse(Buffer.from(h, "base64url").toString());
    const c = JSON.parse(Buffer.from(p, "base64url").toString());
    if (head.alg !== "HS256" || c.iss !== "trustvault") return null;
    if (typeof c.sub !== "string" || typeof c.ver !== "number" || typeof c.iat !== "number" || typeof c.exp !== "number") return null;
    if (c.exp < Date.now() / 1000) return null;
    return c;
  } catch { return null; }
}

export async function setSessionCookie(ctx: Ctx, token: string) {
  ctx.setCookies.push(`${COOKIE_NAME}=${token}; Max-Age=${SETTINGS.sessionMinutes * 60}; Path=/api; HttpOnly; ` +
    `SameSite=Strict${ctx.secure ? "; Secure" : ""}`);
}

export function clearSessionCookie(ctx: Ctx) {
  ctx.setCookies.push(`${COOKIE_NAME}=; Max-Age=0; Path=/api; HttpOnly; SameSite=Strict${ctx.secure ? "; Secure" : ""}`);
}

// ---------------------------------------------------------------------------
// Rate limiting: fixed windows stored in the database, so every function instance shares them
// ---------------------------------------------------------------------------
export async function rateCheck(key: string, limit: number, windowSeconds: number): Promise<void> {
  const k = sha256Hex(key);
  const now = new Date();
  const cutoff = sql`${new Date(now.getTime() - windowSeconds * 1000).toISOString()}::timestamp`;
  const nowSql = sql`${now.toISOString()}::timestamp`;
  const [row] = await db.insert(rateLimits).values({ key: k, windowStart: now, hits: 1 })
    .onConflictDoUpdate({
      target: rateLimits.key,
      set: {
        hits: sql`CASE WHEN ${rateLimits.windowStart} < ${cutoff} THEN 1 ELSE ${rateLimits.hits} + 1 END`,
        windowStart: sql`CASE WHEN ${rateLimits.windowStart} < ${cutoff} THEN ${nowSql} ELSE ${rateLimits.windowStart} END`,
      },
    }).returning({ hits: rateLimits.hits });
  if (row && row.hits > limit) throw new HttpError(429, "Too many requests. Please wait and try again.");
}

// ---------------------------------------------------------------------------
// Lockouts (sign-in and document passcodes): 5 failures -> 15 minutes, per subject *and* IP
// ---------------------------------------------------------------------------
const lockKey = (kind: string, subject: string, ip: string) => sha256Hex(`${kind}|${subject.toLowerCase()}|${ip}`);

export async function lockRemaining(kind: string, subject: string, ip: string): Promise<number> {
  const [row] = await db.select().from(lockouts).where(eq(lockouts.keyHash, lockKey(kind, subject, ip)));
  if (row?.lockedUntil && row.lockedUntil.getTime() > Date.now()) {
    return Math.floor((row.lockedUntil.getTime() - Date.now()) / 1000) + 1;
  }
  return 0;
}

export async function lockFail(kind: string, subject: string, ip: string): Promise<void> {
  const key = lockKey(kind, subject, ip);
  const until = sql`${new Date(Date.now() + SETTINGS.lockoutMinutes * 60_000).toISOString()}::timestamp`;
  const t = SETTINGS.lockoutThreshold;
  await db.insert(lockouts).values({ keyHash: key, failures: 1, updatedAt: new Date() }).onConflictDoUpdate({
    target: lockouts.keyHash,
    set: {
      failures: sql`CASE WHEN ${lockouts.failures} + 1 >= ${t} THEN 0 ELSE ${lockouts.failures} + 1 END`,
      lockedUntil: sql`CASE WHEN ${lockouts.failures} + 1 >= ${t} THEN ${until} ELSE ${lockouts.lockedUntil} END`,
      updatedAt: new Date(),
    },
  });
}

export async function lockClear(kind: string, subject: string, ip: string): Promise<void> {
  await db.delete(lockouts).where(eq(lockouts.keyHash, lockKey(kind, subject, ip)));
}

// ---------------------------------------------------------------------------
// Upload validation: allow-list, double-extension and magic-byte checks
// ---------------------------------------------------------------------------
export const ALLOWED_EXT = new Set(["pdf", "txt", "doc", "docx", "jpg", "jpeg", "png", "webp", "svg"]);
const DANGEROUS_PARTS = new Set(["exe", "js", "html", "htm", "php", "sh", "bat", "cmd", "ps1", "svg", "jar", "msi", "vbs"]);
const MAGIC: Record<string, number[]> = {
  pdf: [0x25, 0x50, 0x44, 0x46], doc: [0xd0, 0xcf, 0x11, 0xe0], docx: [0x50, 0x4b, 0x03, 0x04],
  jpg: [0xff, 0xd8, 0xff], jpeg: [0xff, 0xd8, 0xff], png: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  webp: [0x52, 0x49, 0x46, 0x46],
};
export const MIME: Record<string, string> = {
  pdf: "application/pdf", txt: "text/plain; charset=utf-8", doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", svg: "image/svg+xml",
};
const SVG_START = /^\s*(<\?xml[^>]*\?>\s*)?(<!--[\s\S]*?-->\s*)*<svg[\s>]/i;
const SVG_ACTIVE = /<\s*(script|foreignObject|iframe|object|embed|link|style|animate|set|use|image|a|audio|video)\b|<!(DOCTYPE|ENTITY)|\bon\w+\s*=|javascript:|data:|(?:href|src)\s*=\s*(?!["']?#)|url\s*\(\s*(?!["']?#)/i;

export const extension = (name: string) => name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";

export function validateUpload(rawName: string, data: Uint8Array): string | null {
  const name = cleanFilename(rawName);
  const ext = extension(name);
  if (!name || !ALLOWED_EXT.has(ext)) return `File type .${ext || "?"} is not allowed.`;
  if (name.split(".").slice(1, -1).some(p => DANGEROUS_PARTS.has(p.toLowerCase()))) return "Disguised double extension.";
  if (!data.length) return "Empty file.";
  if (data.length > SETTINGS.maxUploadBytes) return `Larger than ${SETTINGS.maxUploadBytes / 1048576} MiB.`;
  const latin = () => Buffer.from(data).toString("latin1");
  if (ext === "svg") {
    if (data.length > 1024 * 1024) return "SVG larger than 1 MiB.";
    const s = latin();
    if (!SVG_START.test(s)) return "Content does not match .svg.";
    if (SVG_ACTIVE.test(s)) return "SVG contains active or external content.";
    return null;
  }
  if (ext === "txt") {
    if (data.includes(0)) return "Content does not match .txt.";
    try { new TextDecoder("utf-8", { fatal: true }).decode(data); } catch { return "Text files must be UTF-8."; }
    return null;
  }
  const m = MAGIC[ext];
  if (data.length < m.length || !m.every((b, i) => data[i] === b)) return `Content does not match .${ext}.`;
  if (ext === "webp" && Buffer.from(data.slice(8, 12)).toString("latin1") !== "WEBP") return "Content does not match .webp.";
  return null;
}

export const sha256Hex = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");
export const hmacHex = (key: string, msg: string) => createHmac("sha256", key).update(msg).digest("hex");
