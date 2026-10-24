// Builds the one-shot autofill expression an agent runs in a browser page.
// The fill logic lives in web/autofill.js between the @locked:fill markers, so the
// script-tag build and this snippet share one implementation.

import { readFileSync } from "node:fs";
import { join } from "node:path";

const SOURCE = join(import.meta.dir, "..", "web", "autofill.js");
const BEGIN = "// @locked:fill-begin";
const END = "// @locked:fill-end";
/** Stands in for the call's arguments while the template is minified and cached. */
const ARGS = "__LOCKED_FILL_ARGS__";

export type SnippetArgs = {
  /** Locked's public base URL, e.g. https://locked.flypack.app */
  base: string;
  /** One-time autofill token for GET {base}/u/{token}. */
  token: string;
  /** Field name -> CSS selector, for inputs the heuristics miss. */
  map?: Record<string, string>;
  /** Submit the form after filling. */
  submit?: boolean;
  /**
   * When the page's CSP blocks the fetch, navigate through {base}/hop and come back with the
   * values encrypted in the URL fragment (default). The run that hops returns reason "hop"; run
   * the same snippet again once the page has reloaded. false: just return reason "csp".
   */
  hop?: boolean;
};

let template: string | null = null;

/** The lockedFill function's source, exactly as it sits between the markers. */
export function fillSource(): string {
  const src = readFileSync(SOURCE, "utf8");
  const a = src.indexOf(BEGIN);
  const b = src.indexOf(END);
  if (a < 0 || b < a) throw new Error(`web/autofill.js: missing ${BEGIN} / ${END} markers`);
  const fn = src.slice(a + BEGIN.length, b).trim();
  if (!/^async function lockedFill\s*\(/.test(fn)) throw new Error("web/autofill.js: the marked block must be `async function lockedFill(...)`");
  return fn;
}

/** True when `code` parses as one expression: a top-level `;` or statement would not fit inside the parentheses. */
export function isSingleExpression(code: string): boolean {
  try {
    new Function(`return (\n${code}\n)`);
    return true;
  } catch {
    return false;
  }
}

/**
 * `(x)=>` to `x=>`. Safe here because the source has no string that contains `)=>`; an
 * identifier character before the `(` (as in `async(x)=>`) leaves it alone.
 */
function tighten(code: string): string {
  return code.replace(/(^|[^\w$])\(([A-Za-z_$][\w$]*)\)=>/g, "$1$2=>");
}

function wrap(fn: string): string {
  return `(async()=>{${fn};return await lockedFill(${ARGS})})()`;
}

/** Minified, cached `(async()=>{…lockedFill(ARGS)})()` with the argument placeholder in it. */
function snippetTemplate(): string {
  if (template) return template;
  const raw = wrap(fillSource());
  const attempts: Array<Record<string, unknown>> = [
    { loader: "js", minify: { whitespace: true, identifiers: true, syntax: true } },
    { loader: "js", minifyWhitespace: true },
  ];
  for (const options of attempts) {
    try {
      const out = tighten(new Bun.Transpiler(options as any).transformSync(raw).trim().replace(/;$/, ""));
      // Keep the output only if it is still one expression with exactly one placeholder.
      if (out.split(ARGS).length === 2 && isSingleExpression(out.replace(ARGS, "'',''"))) {
        template = out;
        return out;
      }
    } catch {
      // try the next, less aggressive setting
    }
  }
  template = raw;
  return raw;
}

/** JSON, made safe to drop into any JS or HTML context. */
function literal(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * One expression that fetches the payload for `token` from `base`, fills the page and
 * resolves to an AutofillResult (field names, never values). It declares no globals.
 */
export function buildSnippet(args: SnippetArgs): string {
  let base: URL;
  try {
    base = new URL(args.base);
  } catch {
    throw new Error(`buildSnippet: bad base URL ${JSON.stringify(args.base)}`);
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") throw new Error("buildSnippet: base must be http(s)");
  if (typeof args.token !== "string" || !args.token) throw new Error("buildSnippet: token is required");

  const opts: { map?: Record<string, string>; submit?: boolean; hop?: false } = {};
  if (args.map) {
    const map: Record<string, string> = {};
    for (const [name, selector] of Object.entries(args.map)) {
      if (typeof selector !== "string" || !selector) throw new Error(`buildSnippet: map.${name} must be a CSS selector string`);
      map[name] = selector;
    }
    if (Object.keys(map).length) opts.map = map;
  }
  if (args.submit) opts.submit = true;
  if (args.hop === false) opts.hop = false;

  const baseUrl = base.href.replace(/\/+$/, "");
  return snippetTemplate().replace(ARGS, () => [literal(baseUrl), literal(args.token), literal(opts)].join(","));
}
