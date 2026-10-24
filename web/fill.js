// Locked fill page. Renders FillPageData (src/model.ts), encrypts the answer in
// this browser (fill-crypto.js) and POSTs a FillPost to location.pathname.
// Every piece of request data goes into the DOM as text, never as HTML.

import { buildSubmitPost, cryptoAvailable } from "./fill-crypto.js";

const RETENTIONS = [
  ["once", "Delete after first use", "Deleted 5 minutes after Claude first uses it, so multi-step logins still work."],
  ["1h", "Keep 1 hour", "Kept for 1 hour, then deleted."],
  ["24h", "Keep 24 hours", "Kept for 24 hours, then deleted."],
  ["forever", "Keep until I revoke", "Kept, encrypted, until you revoke it."],
];

const DONE_NOTE = {
  once: "Locked deletes it 5 minutes after Claude first uses it.",
  "1h": "Locked deletes it after 1 hour.",
  "24h": "Locked deletes it after 24 hours.",
  forever: "Locked keeps it until you revoke it.",
};

const NO_AUTOFIX = { autocapitalize: "none", autocorrect: "off", spellcheck: "false" };
const INPUT_ATTRS = {
  username: { type: "text", autocomplete: "username", ...NO_AUTOFIX },
  email: { type: "email", autocomplete: "email", ...NO_AUTOFIX },
  password: { type: "password", autocomplete: "current-password", ...NO_AUTOFIX },
  "new-password": { type: "password", autocomplete: "new-password", ...NO_AUTOFIX },
  otp: { type: "text", inputmode: "numeric", autocomplete: "one-time-code", ...NO_AUTOFIX, class: "mono otp" },
  apikey: { type: "password", autocomplete: "off", ...NO_AUTOFIX, class: "mono" },
  url: { type: "url", inputmode: "url", ...NO_AUTOFIX },
  number: { type: "number", inputmode: "decimal", step: "any" },
  text: { type: "text", autocomplete: "off", spellcheck: "false" },
};
const REVEALABLE = new Set(["password", "new-password", "apikey"]);

const STATES = {
  done: { icon: "check", tone: "ok", title: "Sent to Claude", body: "You can close this tab." },
  filled: {
    icon: "check",
    tone: "ok",
    title: "Already sent",
    body: "This request has already been answered. If that wasn't you, tell Claude right away.",
  },
  declined: { icon: "x", tone: "neutral", title: "Declined", body: "This request was declined, so nothing was sent. You can close this tab." },
  expired: {
    icon: "clock",
    tone: "warn",
    title: "This link has expired",
    body: "Nothing was sent. If you still want to share it, ask Claude for a new link.",
  },
  revoked: { icon: "ban", tone: "neutral", title: "This request was revoked", body: "The link doesn't work any more. You can close this tab." },
  missing: {
    icon: "unlink",
    tone: "neutral",
    title: "This Locked link doesn't exist or has been removed",
    body: "Check that you opened the whole link, or ask Claude for a new one.",
  },
  broken: {
    icon: "alert",
    tone: "danger",
    title: "This link can't be used",
    body: "The page is missing some details, so nothing can be sent. Ask Claude for a new link.",
  },
};
const TERMINAL = ["filled", "declined", "expired", "revoked", "missing"];

// ------------------------------------------------------------------ DOM helpers

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid);
  return el;
}

const SVGNS = "http://www.w3.org/2000/svg";
const CIRCLE = ["circle", { cx: 12, cy: 12, r: 9 }];
const ICONS = {
  lock: [["rect", { x: 5, y: 11, width: 14, height: 10, rx: 2.5 }], ["path", { d: "M8 11V8a4 4 0 0 1 8 0v3" }]],
  globe: [CIRCLE, ["path", { d: "M3 12h18M12 3c2.4 2.6 3.6 5.6 3.6 9s-1.2 6.4-3.6 9c-2.4-2.6-3.6-5.6-3.6-9S9.6 5.6 12 3z" }]],
  alert: [["path", { d: "M10.3 4.2a2 2 0 0 1 3.4 0l7.4 12.8a2 2 0 0 1-1.7 3H4.6a2 2 0 0 1-1.7-3z" }], ["path", { d: "M12 9.5v4M12 16.8v.2" }]],
  eye: [["path", { d: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" }], ["circle", { cx: 12, cy: 12, r: 3 }]],
  eyeOff: [
    ["path", { d: "M10.6 5.6c.5-.1.9-.1 1.4-.1 6 0 9.5 6.5 9.5 6.5a16.6 16.6 0 0 1-2.4 3.2M6.6 6.6C3.9 8.4 2.5 12 2.5 12S6 18.5 12 18.5c1.8 0 3.4-.6 4.8-1.4" }],
    ["path", { d: "M9.9 9.9a3 3 0 0 0 4.2 4.2M3.5 3.5l17 17" }],
  ],
  shield: [["path", { d: "M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z" }], ["path", { d: "M9 12l2 2 4-4" }]],
  check: [CIRCLE, ["path", { d: "M8 12.5l2.7 2.7L16.2 9.5" }]],
  x: [CIRCLE, ["path", { d: "M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6" }]],
  clock: [CIRCLE, ["path", { d: "M12 7.5V12l3 2" }]],
  ban: [CIRCLE, ["path", { d: "M5.7 5.7l12.6 12.6" }]],
  unlink: [
    ["path", { d: "M9.5 14.5l5-5M11 6.5l1.2-1.2a4.2 4.2 0 0 1 6 6L17 12.5M13 17.5l-1.2 1.2a4.2 4.2 0 0 1-6-6L7 11.5" }],
    ["path", { d: "M3.5 3.5l17 17" }],
  ],
};

function icon(name, size = 20) {
  const svg = document.createElementNS(SVGNS, "svg");
  const attrs = {
    class: "icon",
    viewBox: "0 0 24 24",
    width: size,
    height: size,
    fill: "none",
    stroke: "currentColor",
    "stroke-width": 1.8,
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
    focusable: "false",
  };
  for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, String(v));
  for (const [tag, a] of ICONS[name] || []) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(a)) el.setAttribute(k, String(v));
    svg.append(el);
  }
  return svg;
}

// ------------------------------------------------------------------ shared bits

const app = document.getElementById("app");
const timerEl = document.getElementById("timer");
let countdown = null;

function readData() {
  const el = document.getElementById("locked-data");
  if (!el) return { state: "missing" };
  try {
    const data = JSON.parse(el.textContent || "");
    return data && typeof data === "object" ? data : { state: "missing" };
  } catch {
    return { state: "missing" };
  }
}

function parseSite(site) {
  if (typeof site !== "string" || site === "") return null;
  try {
    const u = new URL(site);
    if (!u.host) return { host: site, origin: site };
    return { host: u.host, origin: u.origin };
  } catch {
    return { host: site, origin: site };
  }
}

function siteBlock(site) {
  if (!site) {
    return h("div", { class: "site is-none" }, icon("globe", 22), h("div", { class: "site-text" }, h("p", { class: "site-host" }, "Not tied to a website")));
  }
  return h(
    "div",
    { class: "site" },
    icon("globe", 22),
    h("div", { class: "site-text" }, h("p", { class: "site-host" }, "For ", h("strong", null, site.host)), h("p", { class: "site-origin" }, site.origin)),
  );
}

function fmtRemaining(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000));
  const d = Math.floor(s / 86400);
  const hr = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return `${d} d ${hr} h`;
  if (hr > 0) return `${hr} h ${String(m).padStart(2, "0")} min`;
  return `${m}:${String(sec).padStart(2, "0")}`;
}

/** Ticks once a second until expiresAt. Leans on createdAt when this device's clock is clearly off. */
function startCountdown(createdAt, expiresAt, onExpire) {
  const now = Date.now();
  const skewed = Number.isFinite(createdAt) && (now < createdAt - 5000 || now >= expiresAt);
  const offset = skewed ? createdAt - now : 0;
  const remaining = () => expiresAt - (Date.now() + offset);
  const label = h("span", null);
  timerEl.replaceChildren(icon("clock", 16), label);
  timerEl.hidden = false;
  let stopped = false;
  const tick = () => {
    if (stopped) return;
    const left = remaining();
    const text = `Expires in ${fmtRemaining(left)}`;
    label.textContent = text;
    timerEl.setAttribute("aria-label", text);
    timerEl.classList.toggle("is-urgent", left < 60_000);
    if (left <= 0) onExpire();
  };
  const id = setInterval(tick, 1000);
  document.addEventListener("visibilitychange", tick);
  tick();
  return {
    remaining,
    stop() {
      stopped = true;
      clearInterval(id);
      document.removeEventListener("visibilitychange", tick);
      timerEl.hidden = true;
    },
  };
}

function showState(kind, { label, note, focus = false } = {}) {
  countdown?.stop();
  countdown = null;
  const s = STATES[kind] || STATES.missing;
  const title = h("h1", { id: "state-title", class: "state-title", tabindex: "-1" }, s.title);
  app.replaceChildren(
    h(
      "section",
      { class: `card state tone-${s.tone}`, "aria-labelledby": "state-title" },
      h("div", { class: "state-icon" }, icon(s.icon, 28)),
      title,
      label ? h("p", { class: "state-label" }, label) : null,
      h("p", { class: "state-body" }, s.body),
      note ? h("p", { class: "state-note" }, note) : null,
    ),
  );
  document.title = `${s.title} · Locked`;
  if (focus) title.focus();
}

async function postJson(body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30_000);
  let res;
  try {
    res = await fetch(location.pathname, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: ctrl.signal,
    });
  } catch {
    return { ok: false, error: ctrl.signal.aborted ? "timeout" : "network" };
  } finally {
    clearTimeout(timer);
  }
  let json = null;
  try {
    json = await res.json();
  } catch {}
  if (json && typeof json === "object" && typeof json.ok === "boolean") return json;
  return { ok: false, error: res.ok ? "bad-response" : `http-${res.status}` };
}

function terminalFrom(reply) {
  for (const v of [reply.state, reply.error]) if (typeof v === "string" && TERMINAL.includes(v)) return v;
  if (reply.error === "http-404" || reply.error === "not_found") return "missing";
  return null;
}

function errorMessage(code) {
  if (code === "network") return "Couldn't reach Locked. Check your connection and try again.";
  if (code === "timeout") return "Locked took too long to answer. Try again.";
  if (code === "rate") return "Too many tries. Wait a minute, then try again.";
  if (code === "bad-response") return "Locked sent back something unexpected. Try again.";
  if (typeof code === "string" && /^http-\d+$/.test(code)) return `Locked couldn't take it right now (error ${code.slice(5)}). Try again.`;
  if (typeof code === "string" && code.trim()) {
    const msg = code.trim().slice(0, 200);
    return `Locked couldn't take it: ${msg}${/[.!?]$/.test(msg) ? "" : "."}`;
  }
  return "Something went wrong. Try again.";
}

function alertBox() {
  const text = h("p", null);
  const el = h("div", { class: "alert alert-error", role: "alert", hidden: true }, icon("alert", 18), text);
  return {
    el,
    show(msg) {
      text.textContent = msg;
      el.hidden = false;
    },
    hide() {
      el.hidden = true;
      text.textContent = "";
    },
  };
}

// ------------------------------------------------------------------ the open request

function normalizeFields(fields) {
  if (!Array.isArray(fields)) return [];
  return fields
    .filter((f) => f && typeof f.name === "string" && f.name !== "")
    .map((f) => ({
      name: f.name,
      type: Object.hasOwn(INPUT_ATTRS, f.type) || f.type === "textarea" ? f.type : "text",
      label: typeof f.label === "string" && f.label.trim() ? f.label : f.name,
      required: f.required !== false,
    }));
}

function fieldBlock(field, index, hintText) {
  const id = `field-${index}`;
  const hintId = `${id}-hint`;
  const errId = `${id}-error`;
  const common = {
    id,
    name: field.name,
    required: field.required,
    "aria-describedby": [hintText ? hintId : null, errId].filter(Boolean).join(" "),
  };
  let input;
  if (field.type === "textarea") {
    input = h("textarea", { ...common, class: "input mono", rows: 6, autocomplete: "off", ...NO_AUTOFIX });
  } else {
    const { class: extra, ...attrs } = INPUT_ATTRS[field.type];
    input = h("input", { ...common, ...attrs, class: extra ? `input ${extra}` : "input" });
  }

  let control = input;
  if (REVEALABLE.has(field.type)) {
    const toggle = h("button", { type: "button", class: "reveal", "aria-controls": id, "aria-pressed": "false", "aria-label": `Show ${field.label}` }, icon("eye"));
    toggle.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      toggle.setAttribute("aria-pressed", String(show));
      toggle.setAttribute("aria-label", `${show ? "Hide" : "Show"} ${field.label}`);
      toggle.replaceChildren(icon(show ? "eyeOff" : "eye"));
    });
    control = h("div", { class: "input-wrap" }, input, toggle);
  }

  const err = h("p", { id: errId, class: "error-text", hidden: true });
  const setError = (msg) => {
    err.textContent = msg;
    err.hidden = !msg;
    if (msg) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
  };
  input.addEventListener("input", () => {
    if (!err.hidden) setError("");
  });

  const el = h(
    "div",
    { class: "field" },
    h("label", { for: id }, field.label, field.required ? null : h("span", { class: "optional" }, " (optional)")),
    control,
    hintText ? h("p", { id: hintId, class: "hint" }, hintText) : null,
    err,
  );
  return { el, input, field, setError };
}

function retentionBlock(preferred) {
  const initial = RETENTIONS.some(([v]) => v === preferred) ? preferred : "once";
  const select = h(
    "select",
    { id: "retention", name: "retention", class: "input", autocomplete: "off", "aria-describedby": "retention-hint" },
    RETENTIONS.map(([value, text]) => h("option", { value, selected: value === initial }, text)),
  );
  select.value = initial;
  const hint = h("p", { id: "retention-hint", class: "hint" });
  const sync = () => {
    hint.textContent = (RETENTIONS.find(([v]) => v === select.value) || RETENTIONS[0])[2];
  };
  select.addEventListener("change", sync);
  sync();
  return {
    el: h("div", { class: "field" }, h("label", { for: "retention" }, "How long Locked keeps it"), h("div", { class: "select-wrap" }, select), hint),
    select,
  };
}

function renderOpen(d) {
  const fields = normalizeFields(d.fields);
  if (typeof d.id !== "string" || !d.id || typeof d.publicKey !== "string" || !d.publicKey || !fields.length || !Number.isFinite(d.expiresAt)) {
    return showState("broken", { label: d.label });
  }
  const site = parseSite(d.site);
  const label = typeof d.label === "string" && d.label.trim() ? d.label : "A secret";
  const reason = typeof d.reason === "string" ? d.reason.trim() : "";
  document.title = `${label} · Locked`;

  // What is being asked, and for where.
  const request = h(
    "section",
    { class: "card", "aria-labelledby": "req-title" },
    h("h1", { id: "req-title", class: "title" }, label),
    h("p", { class: "ask-label" }, "Claude is asking for:"),
    h("p", { class: reason ? "reason" : "reason is-empty" }, reason || "No reason given."),
    siteBlock(site),
    d.firstTimeSite
      ? h("div", { class: "notice", role: "note" }, icon("alert", 18), h("p", null, "First time Claude asks for a secret for this site — make sure you started this."))
      : null,
    d.level === "sealed"
      ? h("p", { class: "badge badge-sealed" }, icon("shield", 16), h("span", null, "Sealed — Claude can't read it; you approve each use"))
      : h("p", { class: "badge badge-normal" }, icon("eye", 16), h("span", null, "Claude can read this")),
  );

  // The answer form. A native submit must never happen: the first listener cancels it.
  const form = h("form", { class: "form", method: "post", novalidate: true, "aria-label": "Your answer" });
  form.addEventListener("submit", (e) => e.preventDefault());

  let pmHintUsed = false;
  const controls = fields.map((f, i) => {
    let hint = null;
    if (f.type === "password" && site && !pmHintUsed) {
      pmHintUsed = true;
      hint = `Using a password manager? Look for ${site.host} in it.`;
    }
    return fieldBlock(f, i, hint);
  });
  const fieldset = h("fieldset", { class: "fields" }, h("legend", { class: "sr-only" }, "Fields Claude asked for"), controls.map((c) => c.el));
  const retention = retentionBlock(d.retention);
  const formError = alertBox();
  const sendLabel = h("span", null, "Send securely");
  const sendBtn = h("button", { type: "submit", class: "btn btn-primary" }, sendLabel);
  const declineBtn = h("button", { type: "button", class: "btn btn-secondary" }, "Decline");
  form.append(fieldset, retention.el, formError.el, h("div", { class: "actions" }, sendBtn, declineBtn));

  const canEncrypt = cryptoAvailable();
  if (!canEncrypt) {
    formError.show("This browser can't encrypt on this page (it needs a secure https connection), so Locked won't send anything. Open the link in an up-to-date browser.");
    sendBtn.disabled = true;
  }

  // Decline, with an optional note.
  const note = h("textarea", { id: "decline-note", class: "input", rows: 3, maxlength: 500, autocomplete: "off" });
  const declineError = alertBox();
  const declineTitle = h("h2", { class: "section-title", tabindex: "-1" }, "Decline this request?");
  const confirmDecline = h("button", { type: "button", class: "btn btn-danger" }, "Decline request");
  const backBtn = h("button", { type: "button", class: "btn btn-secondary" }, "Back");
  const declinePanel = h(
    "div",
    { class: "decline", hidden: true },
    h("div", null, declineTitle, h("p", { class: "muted" }, "Claude won't get anything. You can tell it why.")),
    h("div", { class: "field" }, h("label", { for: "decline-note" }, "Note for Claude", h("span", { class: "optional" }, " (optional)")), note),
    declineError.el,
    h("div", { class: "actions" }, confirmDecline, backBtn),
  );

  app.replaceChildren(request, h("section", { class: "card", "aria-label": "Your answer" }, form, declinePanel));

  let busy = false;
  let expired = false;

  const clearInputs = () => {
    for (const c of controls) c.input.value = "";
    note.value = "";
  };
  const expire = () => {
    expired = true;
    if (busy) return; // let the in-flight request settle first
    clearInputs();
    showState("expired", { label, focus: true });
  };
  let sendIcon = icon("lock", 18);
  sendBtn.prepend(sendIcon);
  const setBusy = (on, text) => {
    busy = on;
    fieldset.disabled = on;
    retention.select.disabled = on;
    declineBtn.disabled = on;
    sendBtn.disabled = on || !canEncrypt;
    sendBtn.setAttribute("aria-busy", String(on));
    sendLabel.textContent = on ? text : "Send securely";
    const next = on ? h("span", { class: "spinner", "aria-hidden": "true" }) : icon("lock", 18);
    sendIcon.replaceWith(next);
    sendIcon = next;
  };

  form.addEventListener("submit", async () => {
    if (busy || expired) return;
    formError.hide();
    let firstBad = null;
    for (const c of controls) {
      const ok = c.input.checkValidity();
      c.setError(ok ? "" : c.input.validity.valueMissing ? "This one is required." : c.input.validationMessage || "Check this value.");
      if (!ok && !firstBad) firstBad = c.input;
    }
    if (firstBad) return firstBad.focus();

    const keep = retention.select.value;
    setBusy(true, "Encrypting…");
    let body;
    try {
      const values = {};
      for (const c of controls) values[c.field.name] = c.input.value;
      body = await buildSubmitPost(d.publicKey, values, d.id, keep);
    } catch (err) {
      setBusy(false);
      // Never fall back to sending plaintext.
      return formError.show(err instanceof Error && err.message ? err.message : "Couldn't encrypt in this browser, so nothing was sent.");
    }

    setBusy(true, "Sending…");
    const reply = await postJson(body);
    body = null;
    if (reply.ok) {
      clearInputs();
      form.reset();
      const extra = d.level === "sealed" ? " It's sealed: Claude can't read it, and you'll approve each use." : "";
      return showState("done", { label, note: (DONE_NOTE[keep] || "") + extra, focus: true });
    }
    const terminal = terminalFrom(reply);
    if (terminal) {
      clearInputs();
      return showState(terminal, { label, focus: true });
    }
    setBusy(false);
    if (expired) return expire();
    formError.show(`${errorMessage(reply.error)} What you typed is still here.`);
  });

  declineBtn.addEventListener("click", () => {
    form.hidden = true;
    declinePanel.hidden = false;
    declineTitle.focus();
  });
  backBtn.addEventListener("click", () => {
    declinePanel.hidden = true;
    form.hidden = false;
    declineError.hide();
    declineBtn.focus();
  });
  confirmDecline.addEventListener("click", async () => {
    if (busy || expired) return;
    declineError.hide();
    busy = true;
    confirmDecline.disabled = backBtn.disabled = note.disabled = true;
    confirmDecline.setAttribute("aria-busy", "true");
    confirmDecline.textContent = "Declining…";
    const text = note.value.trim();
    const reply = await postJson(text ? { action: "decline", note: text } : { action: "decline" });
    busy = false;
    if (reply.ok) {
      clearInputs();
      return showState("declined", { label, focus: true });
    }
    const terminal = terminalFrom(reply);
    if (terminal) {
      clearInputs();
      return showState(terminal, { label, focus: true });
    }
    confirmDecline.disabled = backBtn.disabled = note.disabled = false;
    confirmDecline.setAttribute("aria-busy", "false");
    confirmDecline.textContent = "Decline request";
    if (expired) return expire();
    declineError.show(errorMessage(reply.error));
  });

  countdown = startCountdown(d.createdAt, d.expiresAt, expire);
}

// ------------------------------------------------------------------ boot

const hostEl = document.getElementById("host");
if (hostEl) hostEl.textContent = location.host;

const data = readData();
if (data.state === "open") renderOpen(data);
else showState(TERMINAL.includes(data.state) ? data.state : "missing", { label: typeof data.label === "string" ? data.label : null });
