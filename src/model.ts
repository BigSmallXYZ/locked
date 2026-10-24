// Shared shapes. The web pages (web/*.js) read the same JSON, so keep them in step.

export type FieldType =
  | "username"
  | "email"
  | "password"
  | "new-password"
  | "otp"
  | "apikey"
  | "text"
  | "textarea"
  | "url"
  | "number";

export const FIELD_TYPES: FieldType[] = ["username", "email", "password", "new-password", "otp", "apikey", "text", "textarea", "url", "number"];

export type Field = {
  name: string;
  type: FieldType;
  label: string;
  required: boolean;
};

export type Level = "normal" | "sealed";
export type Retention = "once" | "1h" | "24h" | "forever";
export const RETENTIONS: Retention[] = ["once", "1h", "24h", "forever"];
export type Status = "pending" | "filled" | "declined" | "expired" | "revoked";
export type Via = "inject" | "exec" | "copy" | "get";

/** Embedded in the fill page as <script type="application/json" id="locked-data">. */
export type FillPageData = {
  state: "open" | "filled" | "declined" | "expired" | "revoked" | "missing";
  id?: string;
  label?: string;
  reason?: string;
  /** Origin the secret is bound to, e.g. "https://github.com". Null when not tied to a site. */
  site?: string | null;
  level?: Level;
  fields?: Field[];
  /** Claude's suggested retention; the user can change it. */
  retention?: Retention;
  /** Request's P-256 public key, raw uncompressed point, base64url. */
  publicKey?: string;
  createdAt?: number;
  expiresAt?: number;
  /** True when no secret has been filled for this site before. */
  firstTimeSite?: boolean;
};

/**
 * POST /r/:token, JSON.
 *   { action: "submit", envelope: FillEnvelope, retention: Retention }
 *     where the envelope's plaintext is { values: Record<fieldName, string> }
 *   { action: "decline", note?: string }
 * Reply: { ok: true, state } or { ok: false, error }.
 */
export type FillPost =
  | { action: "submit"; envelope: import("./crypto.ts").FillEnvelope; retention: Retention }
  | { action: "decline"; note?: string };

/** Embedded in the approve page as <script type="application/json" id="locked-data">. */
export type ApprovePageData = {
  state: "open" | "approved" | "denied" | "expired" | "used" | "missing";
  id?: string;
  requestId?: string;
  label?: string;
  site?: string | null;
  via?: Via;
  purpose?: string;
  fields?: string[];
  createdAt?: number;
  expiresAt?: number;
};

/** POST /a/:token, JSON { decision: "approve" | "deny" }. Reply { ok: true, state } or { ok: false, error }. */
export type ApprovePost = { decision: "approve" | "deny" };

/**
 * GET /u/:token, what the autofill snippet fetches. One use, 60 seconds, CORS bound to one origin.
 * 200 { ok: true, origin, fields: [{ name, type, label, value }] }
 * 403 { ok: false, error: "origin" }   (token burned)
 * 404 { ok: false, error: "missing" }
 * 410 { ok: false, error: "used" | "expired" }
 */
export type AutofillPayload =
  | { ok: true; origin: string; fields: Array<Field & { value: string }> }
  | { ok: false; error: "origin" | "missing" | "used" | "expired" | "rate" };

/** What the injected snippet returns to Claude. Never includes values. */
export type AutofillResult = {
  ok: boolean;
  reason?: "csp" | "hop" | "network" | "origin" | "missing" | "used" | "expired" | "rate" | "no-inputs" | "error";
  message?: string;
  filled: string[];
  missing: string[];
  origin: string;
  submitted?: boolean;
};
