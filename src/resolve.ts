// Find a stored secret by id or by name: `locked get github` instead of `locked get lk_7f3k2m9qpa`.

import type { RequestSummary } from "./requests.ts";

export type Match = { ok: true; request: RequestSummary } | { ok: false; reason: "none" | "ambiguous"; candidates: RequestSummary[] };

const host = (site: string | null) => (site ? site.replace(/^https?:\/\//, "").replace(/:\d+$/, "") : "");

/**
 * An `lk_…` id matches exactly, whatever its state. A name matches only usable (filled) secrets:
 * an exact label first, then a label, site or host containing the query, case-insensitively.
 * When several still match, the most recently filled one with an exact label or host wins;
 * otherwise it's ambiguous and the caller lists the candidates.
 */
export function matchRequest(requests: RequestSummary[], query: string): Match {
  const q = query.trim().toLowerCase();
  if (/^lk_[a-z0-9]+$/.test(q)) {
    const r = requests.find((x) => x.id === q);
    return r ? { ok: true, request: r } : { ok: false, reason: "none", candidates: [] };
  }
  const usable = requests.filter((r) => r.status === "filled").sort((a, b) => (b.filledAt ?? 0) - (a.filledAt ?? 0));
  const exact = usable.filter((r) => r.label.toLowerCase() === q || host(r.site).toLowerCase() === q);
  if (exact.length >= 1) return { ok: true, request: exact[0]! };
  const loose = usable.filter((r) => r.label.toLowerCase().includes(q) || (r.site ?? "").toLowerCase().includes(q));
  if (loose.length === 1) return { ok: true, request: loose[0]! };
  return { ok: false, reason: loose.length ? "ambiguous" : "none", candidates: loose };
}
