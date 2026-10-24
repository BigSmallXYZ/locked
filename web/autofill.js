/*
 * Locked autofill: fill a page's login inputs from a one-time Locked payload
 * without handing the values back to whoever ran the code.
 *
 * Two ways in:
 *  - src/inject.ts cuts lockedFill() out from between the markers below and wraps it in a
 *    one-shot expression that an agent runs in the page (its browser JavaScript tool).
 *    So lockedFill must stay self-contained: every helper lives inside it.
 *  - As a script tag:
 *      <script src="{base}/inject.js" data-token="…" data-submit data-map='{"password":"#pw"}'></script>
 *    It fills, then dispatches a "locked:autofill" CustomEvent on document with the
 *    result, and exposes window.Locked.fill(token, opts). The base is the script's origin.
 *
 * The result (AutofillResult in src/model.ts) lists field names only, never values.
 *
 * CSP hop: when the page's CSP blocks the fetch, lockedFill makes an AES-GCM key, keeps it in
 * sessionStorage["locked:hop"] and navigates to {base}/hop#t=…&k=…&r=<this page>. Locked's hop
 * page fetches the payload from its own origin, encrypts it with k and comes straight back with
 * #locked=<base64url(iv || ciphertext)> (or #locked-error=<code>). Running lockedFill again on
 * the page then decrypts and fills; top-level navigation isn't something CSP can block.
 */
(function () {
  "use strict";

  // @locked:fill-begin
  async function lockedFill(base, token, opts) {
    opts = opts || {};
    let map = opts.map, submit = opts.submit;
    const here = location.origin, proto = Object.getPrototypeOf;
    const res = { ok: false, filled: [], missing: [], origin: here };
    const fail = (reason, message) => ({ ...res, ok: false, reason, message });
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const low = (s) => String(s || "").toLowerCase();
    const norm = (s) => low(s).replace(/[^a-z0-9]/g, "");
    const kind = (el) => el.type; // lowercase for inputs; "textarea" for textareas
    const attr = (el, n) => el.getAttribute(n) || "";
    const isField = (el) => /^(input|textarea)$/.test(el.localName);
    const NEW = "new-password", CSP = "securitypolicyviolation", HOP = "locked:hop", subtle = crypto.subtle;
    const b64e = (u) => btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const b64d = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const codes = /^(origin|missing|used|expired|rate)$/;
    let fields = [];
    const wipe = () => {
      for (const f of fields) f.value = "";
      fields = [];
    };

    // Inputs in the document, open shadow roots and same-origin iframes, in document order.
    let roots, els, pool;
    const walk = (root) => {
      roots.push(root);
      for (const el of root.querySelectorAll("*")) {
        if (isField(el)) els.push(el);
        if (el.shadowRoot) walk(el.shadowRoot);
        try {
          if (el.contentDocument) walk(el.contentDocument);
        } catch (e) {} // cross-origin frame
      }
    };
    const usable = (el) => !el.disabled && !el.readOnly;
    const visible = (el) => {
      if (!usable(el) || !/^(text|email|tel|password|number|url|textarea)$/.test(kind(el))) return false;
      if (el.checkVisibility?.({ checkVisibilityCSS: true }) == false) return false;
      const r = el.getBoundingClientRect(), w = el.ownerDocument.defaultView;
      return r.width > 1 && r.height > 1 && r.right + w.scrollX > 0 && r.bottom + w.scrollY > 0;
    };
    const scan = () => {
      roots = [];
      els = [];
      walk(document);
      pool = els.filter(visible);
    };
    const used = new Set();
    const free = (el) => el && !used.has(el);
    const first = (list) => list.find(free);
    const byMap = (sel) => {
      for (const root of roots) {
        try {
          for (const el of root.querySelectorAll(sel)) if (isField(el) && usable(el) && free(el)) return el;
        } catch (e) {} // bad selector
      }
    };

    try {
      // Back from a CSP hop? This comes first and never touches the token.
      let store, saved, resp, data;
      try {
        store = sessionStorage;
        saved = JSON.parse(store.getItem(HOP));
      } catch (e) {}
      const back = saved && /^#locked=([\w-]+)$/.exec(location.hash), err = saved && /^#locked-error=(\w+)$/.exec(location.hash);
      const clear = () => {
        store.removeItem(HOP);
        history.replaceState(null, "", location.pathname + location.search);
      };
      if (err) return clear(), fail(codes.test(err[1]) ? err[1] : "error");
      if (back) (map ||= saved.map), (submit ??= saved.submit);
      else if (saved && Date.now() - saved.at > 18e4) store.removeItem(HOP); // a hop that never came back
      map ||= {};

      // Look before fetching, so a page with nothing to fill doesn't burn the token.
      scan();
      const any = () => pool.length || Object.values(map).some(byMap);
      for (let i = 0; !any() && i < 8; i++) await sleep(150), scan();
      if (!any()) return fail("no-inputs", back ? "No fillable inputs yet; run again." : "No fillable inputs; token not used.");

      if (back) {
        clear(); // first, so a bad blob or key can't wedge every later run
        const blob = b64d(back[1]), key = await subtle.importKey("raw", b64d(saved.k), "AES-GCM", false, ["decrypt"]);
        data = JSON.parse(new TextDecoder().decode(await subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) }, key, blob.slice(12))));
      } else {
        const origin = new URL(base).origin;
        let csp = false;
        const onCsp = (e) => (csp ||= String(e.blockedURI).startsWith(origin));
        document.addEventListener(CSP, onCsp, true);
        try {
          resp = await fetch(base.replace(/\/+$/, "") + "/u/" + encodeURIComponent(token), {
            credentials: "omit",
            mode: "cors",
            cache: "no-store",
            referrerPolicy: "no-referrer",
            redirect: "error",
          });
        } catch (e) {
          await sleep(50); // the violation event can land after the rejection
        }
        document.removeEventListener(CSP, onCsp, true);
        if (!resp) {
          // CSP blocked the fetch: hop through Locked by top-level navigation (needs WebCrypto, so a secure context).
          if (csp && opts.hop !== false && subtle && store) {
            const k = b64e(crypto.getRandomValues(new Uint8Array(32)));
            store.setItem(HOP, JSON.stringify({ k, at: Date.now(), map: opts.map, submit: !!opts.submit }));
            location.assign(base.replace(/\/+$/, "") + "/hop#t=" + encodeURIComponent(token) + "&k=" + k + "&r=" + encodeURIComponent(location.href));
            return fail("hop", "Reloading through Locked to get past this page's CSP. When the page has loaded again, run the same snippet again.");
          }
          return fail(csp ? "csp" : "network");
        }
        try {
          data = await resp.json();
        } catch (e) {}
      }
      if (!data?.ok) return fail(codes.test(data?.error) ? data.error : { 403: "origin", 404: "missing", 410: "expired", 429: "rate" }[resp?.status] || "error");
      fields = data.fields || [];
      if (data.origin && data.origin != here) return fail("origin");
      data = null;

      // Match fields to inputs.
      scan();
      const ac = (el, t) => low(attr(el, "autocomplete")).split(/\s+/).includes(t);
      const hay = (el) => {
        let s = [el.name, el.id, attr(el, "placeholder"), attr(el, "aria-label")].join(" ");
        for (const l of el.labels || []) s += " " + l.textContent;
        return s;
      };
      const pw = pool.filter((el) => kind(el) == "password");
      const pi = pool.indexOf(pw[0]);
      const texty = (el) => /^(text|email|tel)$/.test(kind(el));
      // The text input right before the first password input.
      const prev = pool.slice(0, pi > 0 ? pi : 0).filter(texty).pop();

      const pwCurrent = () => first(pw.filter((el) => ac(el, "current-password"))) || first(pw.filter((el) => !ac(el, NEW)));
      const pwNew = () => {
        // Else the first free password box not labelled current/old: after "password" took the first, that is the second.
        const el = first(pw.filter((el) => ac(el, NEW))) || first(pw.filter((el) => !/current|old/i.test(hay(el))));
        const next = pw[pw.indexOf(el) + 1]; // a "confirm password" box right after it gets the same value
        return el && [el, free(next) && (ac(next, NEW) || /confirm|repeat|again|retype/i.test(hay(next))) && next];
      };
      const otp = () => {
        const one = pool.filter((el) => el.maxLength != 1 && free(el));
        const byAc = one.find((el) => ac(el, "one-time-code"));
        if (byAc) return byAc;
        // Split boxes: a run of 4+ one-character inputs.
        let run = [];
        for (const el of pool.concat(0)) {
          if (el && el.maxLength == 1 && free(el)) run.push(el);
          else if (run[3]) return run;
          else run = [];
        }
        return one.find((el) => /otp|code|totp|2fa|mfa|verif|one.?time/i.test(el.name + " " + el.id));
      };
      const score = (f, el) => {
        const t = f.type, h = hay(el), H = norm(h), user = t == "username" || t == "email";
        if (!free(el) || (kind(el) == "password" && t != "apikey") || (user && !texty(el))) return 0;
        let s = 0;
        for (const w of [norm(f.name), norm(f.label)]) if (w.length > 2 && H.includes(w)) s += 4;
        // username/email: its autocomplete token, any login-ish hint, the box before the password
        if (user) s += (ac(el, t) ? 9 : 0) + (/user|login|mail|account|identifier/i.test(h + attr(el, "autocomplete") + kind(el)) ? 3 : 0) + (el == prev ? 2 : 0);
        if (t == "apikey" && /api.?key|token|secret/i.test(h)) s += 3;
        if (s && user && el.form && el.form == pw[0]?.form) s += 5;
        if (s && kind(el) == t) s++;
        return s;
      };
      const best = (f) => {
        let top = 0, out;
        for (const el of pool) {
          const s = score(f, el);
          if (s > top) (top = s), (out = el);
        }
        return out;
      };

      // Fill each field as soon as it has its inputs: mapped fields first, then passwords, codes, the rest.
      const put = (el, v) => {
        let p = proto(el), d;
        while (p && !(d = Object.getOwnPropertyDescriptor(p, "value"))) p = proto(p);
        el.focus({ preventScroll: true });
        // The prototype's setter, so React's per-element value tracker sees a real change.
        d?.set ? d.set.call(el, v) : (el.value = v);
        for (const n of ["input", "change"]) el.dispatchEvent(new el.ownerDocument.defaultView.Event(n, { bubbles: true, composed: true }));
        el.blur();
      };
      const done = new Set();
      let last;
      const take = (f, list, split) => {
        list = list.filter(free);
        if (!list[0]) return;
        const v = String(f.value ?? ""), c = v.replace(/[\s-]/g, "");
        list.forEach((el, i) => {
          used.add(el);
          if (!split) put(el, v);
          else if (c[i]) put(el, c[i]); // split code boxes get one character each
        });
        if (!v || list.some((el) => el.value.length)) done.add(f), (last = list.at(-1));
      };
      const rank = { password: 1, [NEW]: 2, otp: 3 };
      for (const f of fields) if (map[f.name]) take(f, [byMap(map[f.name])]);
      for (const f of [...fields].sort((a, b) => (rank[a.type] || 9) - (rank[b.type] || 9))) {
        if (done.has(f)) continue;
        const t = f.type;
        const got = t == "password" ? pwCurrent() : t == NEW ? pwNew() : t == "otp" ? otp() : 0;
        take(f, [].concat(got || best(f)), t == "otp" && Array.isArray(got));
      }
      for (const f of fields) res[done.has(f) ? "filled" : "missing"].push(f.name);
      wipe();

      if (!done.size) return fail("no-inputs", "No input matched; token used.");
      res.ok = true;
      if (res.missing[0]) res.message = "Multi-step login? Fill the next step with a new token.";

      if (submit) {
        await sleep(120); // let the page re-render (e.g. enable its button)
        const form = last.form, btn = form && [...form.elements].find((e) => kind(e) == "submit");
        const why = !form ? "No form to submit." : btn?.disabled ? "Submit button disabled." : !form.checkValidity() ? "Form has invalid fields." : "";
        res.submitted = !why;
        if (why) res.message = why;
        else btn ? btn.click() : form.requestSubmit();
      }
      return res;
    } catch (e) {
      // Only the error's type: its message could quote page state.
      return fail("error", e?.name);
    } finally {
      wipe();
    }
  }
  // @locked:fill-end

  // Script-tag mode.
  const me = document.currentScript;
  let base = null;
  try {
    base = new URL(me.src).origin;
  } catch (e) {}
  window.Locked = { fill: (token, opts) => lockedFill(base, token, opts) };
  const token = me && me.dataset.token;
  if (!base || !token) return;
  let map;
  try {
    map = me.dataset.map ? JSON.parse(me.dataset.map) : undefined;
  } catch (e) {}
  const submit = me.hasAttribute("data-submit") && me.dataset.submit !== "false";
  const go = () =>
    lockedFill(base, token, { map, submit }).then((detail) => document.dispatchEvent(new CustomEvent("locked:autofill", { detail })));
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", go, { once: true });
  else go();
})();
