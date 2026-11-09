/** Small HTTP toolkit: errors, JSON bodies, cookies, request context, input validation. */

export class HttpError extends Error {
  constructor(public status: number, public detail: string, public headers: Record<string, string> = {}) {
    super(detail);
  }
}

export interface Ctx {
  req: Request;
  url: URL;
  ip: string;
  params: Record<string, string>;
  cookies: Record<string, string>;
  setCookies: string[];
  secure: boolean;
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) {
      const k = part.slice(0, i).trim();
      try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* ignore malformed */ }
    }
  }
  return out;
}

export async function readJson(ctx: Ctx): Promise<Record<string, unknown>> {
  const type = ctx.req.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new HttpError(415, "Send a JSON body.");
  let v: unknown;
  try { v = await ctx.req.json(); } catch { throw new HttpError(422, "Invalid request: body is not valid JSON"); }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new HttpError(422, "Invalid request: expected an object");
  return v as Record<string, unknown>;
}

type StrField = { t: "str"; min?: number; max: number; opt?: boolean; nullable?: boolean; oneOf?: readonly string[]; def?: string };
type BoolField = { t: "bool"; def?: boolean };
export type Field = StrField | BoolField;

/** Validate a JSON object against a spec. Unknown fields are rejected, like the original API. */
export function check<S extends Record<string, Field>>(raw: Record<string, unknown>, spec: S): Record<keyof S, any> {
  for (const k of Object.keys(raw)) if (!(k in spec)) throw new HttpError(422, `Invalid ${k}: Extra inputs are not permitted`);
  const out: Record<string, unknown> = {};
  for (const [k, f] of Object.entries(spec)) {
    const v = raw[k];
    if (f.t === "bool") {
      if (v === undefined) { out[k] = f.def ?? false; continue; }
      if (typeof v !== "boolean") throw new HttpError(422, `Invalid ${k}: Input should be a valid boolean`);
      out[k] = v; continue;
    }
    if (v === undefined || (v === null && f.nullable)) {
      if (f.def !== undefined) { out[k] = f.def; continue; }
      if (f.opt || f.nullable) { out[k] = null; continue; }
      throw new HttpError(422, `Invalid ${k}: Field required`);
    }
    if (typeof v !== "string") throw new HttpError(422, `Invalid ${k}: Input should be a valid string`);
    if (f.min !== undefined && v.length < f.min) throw new HttpError(422, `Invalid ${k}: String should have at least ${f.min} characters`);
    if (v.length > f.max) throw new HttpError(422, `Invalid ${k}: String should have at most ${f.max} characters`);
    if (f.oneOf && !f.oneOf.includes(v)) throw new HttpError(422, `Invalid ${k}: Input should be ${f.oneOf.map(x => `'${x}'`).join(" or ")}`);
    out[k] = v;
  }
  return out as Record<keyof S, any>;
}

export const json = (data: unknown, status = 200) => Response.json(data, { status });
