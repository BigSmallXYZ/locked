import { describe, expect, test } from "bun:test";
import type { RequestSummary } from "../src/requests.ts";
import { matchRequest } from "../src/resolve.ts";

let n = 0;
function req(label: string, site: string | null, extra: Partial<RequestSummary> = {}): RequestSummary {
  n++;
  return {
    id: `lk_${n.toString().padStart(10, "0")}`,
    label,
    reason: "",
    site,
    level: "normal",
    status: "filled",
    fields: [],
    retention: "forever",
    useCount: 0,
    createdAt: n,
    linkExpiresAt: n,
    openedAt: n,
    filledAt: n,
    secretExpiresAt: null,
    declineNote: null,
    ...extra,
  };
}

const github = req("GitHub login", "https://github.com");
const githubOld = req("GitHub token", "https://github.com", { filledAt: 0 });
const aws = req("AWS console", "https://signin.aws.amazon.com");
const pending = req("Bank", "https://bank.example", { status: "pending" });
const all = [github, githubOld, aws, pending];

describe("matchRequest", () => {
  test("ids match exactly", () => {
    expect(matchRequest(all, aws.id)).toEqual({ ok: true, request: aws });
    expect(matchRequest(all, "lk_nothere000")).toMatchObject({ ok: false, reason: "none" });
  });

  test("exact label or host wins, newest first", () => {
    expect(matchRequest(all, "aws console")).toMatchObject({ ok: true, request: aws });
    expect(matchRequest(all, "GitHub.com")).toMatchObject({ ok: true, request: github });
  });

  test("a unique substring of a label or site matches", () => {
    expect(matchRequest(all, "amazon")).toMatchObject({ ok: true, request: aws });
    expect(matchRequest(all, "token")).toMatchObject({ ok: true, request: githubOld });
  });

  test("several loose matches are ambiguous; unfilled ones never match", () => {
    const m = matchRequest(all, "git");
    expect(m).toMatchObject({ ok: false, reason: "ambiguous" });
    if (!m.ok) expect(m.candidates.map((r) => r.id)).toEqual([github.id, githubOld.id]);
    expect(matchRequest(all, "bank")).toMatchObject({ ok: false, reason: "none" });
  });
});
