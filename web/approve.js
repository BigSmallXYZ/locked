// Locked approve page. Renders ApprovePageData (src/model.ts) and POSTs an
// ApprovePost { decision } to location.pathname. Request data is only ever set as text.

const STATES = {
  approved: { icon: "check", tone: "ok", title: "Approved", body: "Claude can go ahead with this one use. You can close this tab." },
  denied: { icon: "x", tone: "neutral", title: "Denied", body: "Claude won't get it this time. You can close this tab." },
  expired: { icon: "clock", tone: "warn", title: "This approval has expired", body: "Nothing was used. If Claude still needs it, it will ask again." },
  used: { icon: "check", tone: "neutral", title: "Already used", body: "This approval has already been acted on. Nothing more to do here." },
  missing: {
    icon: "unlink",
    tone: "neutral",
    title: "This Locked link doesn't exist or has been removed",
    body: "Check that you opened the whole link, or ask Claude for a new one.",
  },
  broken: { icon: "alert", tone: "danger", title: "This link can't be used", body: "The page is missing some details. Nothing was approved." },
};
const TERMINAL = ["approved", "denied", "expired", "used", "missing"];

// ------------------------------------------------------------------ DOM helpers (same as fill.js)

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
  globe: [CIRCLE, ["path", { d: "M3 12h18M12 3c2.4 2.6 3.6 5.6 3.6 9s-1.2 6.4-3.6 9c-2.4-2.6-3.6-5.6-3.6-9S9.6 5.6 12 3z" }]],
  alert: [["path", { d: "M10.3 4.2a2 2 0 0 1 3.4 0l7.4 12.8a2 2 0 0 1-1.7 3H4.6a2 2 0 0 1-1.7-3z" }], ["path", { d: "M12 9.5v4M12 16.8v.2" }]],
  check: [CIRCLE, ["path", { d: "M8 12.5l2.7 2.7L16.2 9.5" }]],
  x: [CIRCLE, ["path", { d: "M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6" }]],
  clock: [CIRCLE, ["path", { d: "M12 7.5V12l3 2" }]],
  unlink: [
    ["path", { d: "M9.5 14.5l5-5M11 6.5l1.2-1.2a4.2 4.2 0 0 1 6 6L17 12.5M13 17.5l-1.2 1.2a4.2 4.2 0 0 1-6-6L7 11.5" }],
    ["path", { d: "M3.5 3.5l17 17" }],
  ],
  form: [["rect", { x: 3.5, y: 5, width: 17, height: 6, rx: 1.8 }], ["rect", { x: 3.5, y: 13.5, width: 17, height: 6, rx: 1.8 }], ["path", { d: "M7 8h.01M7 16.5h4" }]],
  terminal: [["rect", { x: 3, y: 4.5, width: 18, height: 15, rx: 2.5 }], ["path", { d: "M7.5 10l3 2.5-3 2.5M13 15h3.5" }]],
  clipboard: [["rect", { x: 5.5, y: 4.5, width: 13, height: 16, rx: 2 }], ["path", { d: "M9.5 3.5h5v3h-5zM9 11.5h6M9 15h4" }]],
  key: [["circle", { cx: 8, cy: 15, r: 4 }], ["path", { d: "M11 12l8.5-8.5M16 7l2.5 2.5M13.5 9.5l2 2" }]],
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

function startCountdown(createdAt, expiresAt, onExpire) {
  const now = Date.now();
  const skewed = Number.isFinite(createdAt) && (now < createdAt - 5000 || now >= expiresAt);
  const offset = skewed ? createdAt - now : 0;
  const label = h("span", null);
  timerEl.replaceChildren(icon("clock", 16), label);
  timerEl.hidden = false;
  let stopped = false;
  const tick = () => {
    if (stopped) return;
    const left = expiresAt - (Date.now() + offset);
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
    stop() {
      stopped = true;
      clearInterval(id);
      document.removeEventListener("visibilitychange", tick);
      timerEl.hidden = true;
    },
  };
}

function showState(kind, { label, focus = false } = {}) {
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

function errorMessage(code) {
  if (code === "network") return "Couldn't reach Locked. Check your connection and try again.";
  if (code === "timeout") return "Locked took too long to answer. Try again.";
  if (code === "rate") return "Too many tries. Wait a minute, then try again.";
  if (code === "bad-response") return "Locked sent back something unexpected. Try again.";
  if (typeof code === "string" && /^http-\d+$/.test(code)) return `Locked couldn't record that right now (error ${code.slice(5)}). Try again.`;
  if (typeof code === "string" && code.trim()) {
    const msg = code.trim().slice(0, 200);
    return `Locked couldn't record that: ${msg}${/[.!?]$/.test(msg) ? "" : "."}`;
  }
  return "Something went wrong. Try again.";
}

// ------------------------------------------------------------------ the open approval

function howText(via, site) {
  switch (via) {
    case "inject":
      return ["form", `Fill it into the login form on ${site ? site.host : "the site"}`];
    case "exec":
      return ["terminal", "Pass it to a command on your Mac"];
    case "copy":
      return ["clipboard", "Put it on your Mac's clipboard for 30 s"];
    case "get":
      return ["key", "Show the value to Claude"];
    default:
      return ["key", typeof via === "string" && via ? via : "Use it once"];
  }
}

function renderOpen(d) {
  if (!Number.isFinite(d.expiresAt)) return showState("broken", { label: d.label });
  const site = parseSite(d.site);
  const label = typeof d.label === "string" && d.label.trim() ? d.label : "a secret";
  const purpose = typeof d.purpose === "string" ? d.purpose.trim() : "";
  const fields = Array.isArray(d.fields) ? d.fields.filter((f) => typeof f === "string" && f) : [];
  const [howIcon, how] = howText(d.via, site);
  document.title = `Approve ${label} · Locked`;

  const errText = h("p", null);
  const errBox = h("div", { class: "alert alert-error", role: "alert", hidden: true }, icon("alert", 18), errText);
  const approveLabel = h("span", null, "Approve");
  const denyLabel = h("span", null, "Deny");
  const approveBtn = h("button", { type: "button", class: "btn btn-primary" }, approveLabel);
  const denyBtn = h("button", { type: "button", class: "btn btn-secondary" }, denyLabel);

  const detail = (term, ...value) => h("div", { class: "detail" }, h("dt", null, term), h("dd", null, ...value));

  app.replaceChildren(
    h(
      "section",
      { class: "card", "aria-labelledby": "req-title" },
      h("p", { class: "eyebrow" }, "Approval needed"),
      h("h1", { id: "req-title", class: "title" }, "Claude wants to use ", h("strong", null, label)),
      h(
        "dl",
        { class: "details" },
        detail("Why", h("span", { class: purpose ? "reason" : "reason is-empty" }, purpose || "No reason given.")),
        detail("Where", siteBlock(site)),
        detail("How", h("span", { class: "how" }, icon(howIcon, 20), h("span", null, how))),
        fields.length ? detail(fields.length === 1 ? "Field" : "Fields", h("ul", { class: "chips" }, fields.map((f) => h("li", { class: "chip" }, f)))) : null,
      ),
      h("p", { class: "caution" }, "Only approve if you asked Claude to do this just now."),
    ),
    h("section", { class: "card stack", "aria-label": "Your decision" }, errBox, h("div", { class: "actions actions-split" }, approveBtn, denyBtn)),
  );

  let busy = false;
  let expired = false;
  const expire = () => {
    expired = true;
    if (!busy) showState("expired", { label: d.label, focus: true });
  };

  const decide = async (decision) => {
    if (busy || expired) return;
    busy = true;
    errBox.hidden = true;
    approveBtn.disabled = denyBtn.disabled = true;
    const btn = decision === "approve" ? approveBtn : denyBtn;
    const lbl = decision === "approve" ? approveLabel : denyLabel;
    btn.setAttribute("aria-busy", "true");
    lbl.textContent = decision === "approve" ? "Approving…" : "Denying…";
    const reply = await postJson({ decision });
    busy = false;
    if (reply.ok) {
      const state = TERMINAL.includes(reply.state) ? reply.state : decision === "approve" ? "approved" : "denied";
      return showState(state, { label: d.label, focus: true });
    }
    for (const v of [reply.state, reply.error]) {
      if (typeof v === "string" && TERMINAL.includes(v)) return showState(v, { label: d.label, focus: true });
    }
    if (reply.error === "http-404") return showState("missing", { focus: true });
    approveBtn.disabled = denyBtn.disabled = false;
    btn.setAttribute("aria-busy", "false");
    approveLabel.textContent = "Approve";
    denyLabel.textContent = "Deny";
    if (expired) return expire();
    errText.textContent = errorMessage(reply.error);
    errBox.hidden = false;
  };
  approveBtn.addEventListener("click", () => decide("approve"));
  denyBtn.addEventListener("click", () => decide("deny"));

  countdown = startCountdown(d.createdAt, d.expiresAt, expire);
}

// ------------------------------------------------------------------ boot

const hostEl = document.getElementById("host");
if (hostEl) hostEl.textContent = location.host;

const data = readData();
if (data.state === "open") renderOpen(data);
else showState(TERMINAL.includes(data.state) ? data.state : "missing", { label: typeof data.label === "string" ? data.label : null });
