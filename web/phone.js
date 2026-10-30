// The paired phone's web app (/phone/). Three screens:
//   #pair=CODE  pair this phone: allow notifications, create a passkey (server/phone.ts pairBegin/pairFinish)
//   #s=TOKEN    a share your agent sent: Face ID releases the values, sealed to a key made here
//   (nothing)   what's paired, and recent shares
// Values only ever live in this page's memory, and are wiped on Done, on expiry, or after a while in
// the background. Must stay in step with sealFillEnvelope(…, PHONE_INFO) in src/crypto.ts:
//   shared = ECDH(page key, server ephemeral) → HKDF-SHA256(salt, "locked/phone/v1") → AES-GCM, aad = share id

import { b64uDecode, b64uEncode } from "/assets/fill-crypto.js";

const PHONE_INFO = "locked/phone/v1";
const WIPE_AFTER_HIDDEN_MS = 2 * 60_000;
const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = globalThis.crypto?.subtle;

const app = document.getElementById("app");
const timerEl = document.getElementById("timer");
const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
const pushSupported = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const unlockWord = ios ? "Face ID" : "your fingerprint or screen lock";

// --- tiny DOM helpers (text only: nothing from the server is parsed as HTML) ---

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
const show = (...nodes) => app.replaceChildren(...nodes);

function stateCard(title, body, tone = "") {
  return h("section", { class: `card state ${tone}` }, h("h1", { class: "state-title" }, title), body ? h("p", { class: "state-body" }, body) : null);
}

function errorBox(message) {
  return h("div", { class: "alert alert-error", role: "alert" }, h("span", {}, message));
}

function busy(button, label) {
  button.disabled = true;
  button.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), label);
}

async function api(method, path, body) {
  // Every POST is JSON (the server refuses anything else), even with nothing to say.
  if (method === "POST") body ??= {};
  const res = await fetch(`/phone/api/${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "omit",
    cache: "no-store",
  });
  const data = await res.json().catch(() => ({ ok: false, error: `Locked answered ${res.status}` }));
  if (!res.ok || data.ok === false) {
    const e = new Error(data.error || `Locked answered ${res.status}`);
    e.code = data.code;
    e.status = res.status;
    throw e;
  }
  return data;
}

/** What the current screen does when the app comes back from the background (the share screen re-locks). */
let onVisible = null;
/** The share screen's challenge refresher; every screen change stops it. */
let refresher = null;
let hiddenAt = 0;
document.addEventListener("visibilitychange", () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (onVisible) onVisible(Date.now() - hiddenAt);
});

let countdown = null;
function startTimer(expiresAt, onEnd) {
  clearInterval(countdown);
  const tick = () => {
    const left = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
    timerEl.hidden = false;
    timerEl.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    if (left === 0) {
      clearInterval(countdown);
      onEnd();
    }
  };
  tick();
  countdown = setInterval(tick, 1000);
}
function stopTimer() {
  clearInterval(countdown);
  timerEl.hidden = true;
}

const device = {
  get() {
    try {
      return JSON.parse(localStorage.getItem("locked:device") || "null");
    } catch {
      return null;
    }
  },
  set(d) {
    try {
      localStorage.setItem("locked:device", JSON.stringify(d));
    } catch {}
  },
};

let registration = null;
async function serviceWorker() {
  registration ??= await navigator.serviceWorker.register("/phone/sw.js", { scope: "/phone/" });
  await navigator.serviceWorker.ready;
  return registration;
}

// --- pairing ---

function addToHomeScreen(code) {
  const steps = h(
    "ol",
    { class: "steps" },
    h("li", {}, "Tap the Share button in Safari."),
    h("li", {}, "Choose ", h("strong", {}, "Add to Home Screen"), ", then Add."),
    h("li", {}, "Open ", h("strong", {}, "Locked"), " from your Home Screen and enter this code:"),
  );
  show(
    h(
      "section",
      { class: "card" },
      h("p", { class: "eyebrow" }, "Pair this iPhone"),
      h("h1", { class: "title" }, "Add Locked to your Home Screen"),
      h("p", { class: "muted lead" }, "iPhone only lets web apps on the Home Screen show notifications."),
      steps,
      code ? h("p", { class: "code", "aria-label": `code ${code}` }, code) : h("p", { class: "muted" }, "On the Mac, `locked phone pair` gives you the code."),
    ),
  );
}

function pairView(code) {
  stopTimer();
  onVisible = null;
  clearInterval(refresher);
  if (!subtle) return show(stateCard("This page needs a secure connection", "Open it from https://, not a copied file or an http link."));
  if (ios && !standalone) return addToHomeScreen(code);
  if (!pushSupported) return show(stateCard("No notifications in this browser", "Use Safari on iPhone (iOS 16.4 or later, from the Home Screen), or Chrome on Android."));
  if (!window.PublicKeyCredential) return show(stateCard("No passkeys in this browser", "Update the phone, or use Safari on iPhone or Chrome on Android."));

  const vapid = api("GET", "info").then((r) => r.vapidPublicKey);
  vapid.catch(() => {});
  serviceWorker().catch(() => {});

  const codeInput = h("input", { class: "input code-input", id: "code", value: code || "", autocomplete: "one-time-code", autocapitalize: "characters", spellcheck: "false", placeholder: "ABCD-EFGH", maxlength: "12" });
  const nameInput = h("input", { class: "input", id: "name", value: ios ? "iPhone" : "Android phone", maxlength: "60", autocomplete: "off" });
  const status = h("div", { class: "pair-status" });
  const step1 = h("button", { class: "btn btn-primary", type: "button" }, "Allow notifications");
  const card = h(
    "section",
    { class: "card" },
    h("p", { class: "eyebrow" }, "Pair this phone"),
    h("h1", { class: "title" }, "Get credentials from your agent here"),
    h("p", { class: "muted lead" }, `When your agent needs you to use a login on this phone, it sends a notification. Tapping it opens the credential after ${unlockWord}.`),
    h("div", { class: "fields" }, h("div", { class: "field" }, h("label", { for: "code" }, "Code from the Mac"), codeInput), h("div", { class: "field" }, h("label", { for: "name" }, "Name for this phone"), nameInput)),
    status,
    h("div", { class: "actions" }, step1),
  );
  show(card);

  let subscription = null;
  let begun = null;

  async function subscribe() {
    const reg = await serviceWorker();
    const key = b64uDecode(await vapid);
    let sub = await reg.pushManager.getSubscription();
    const current = sub?.options?.applicationServerKey ? new Uint8Array(sub.options.applicationServerKey) : null;
    if (sub && (!current || current.length !== key.length || current.some((b, i) => b !== key[i]))) {
      await sub.unsubscribe();
      sub = null;
    }
    return sub ?? (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key }));
  }

  step1.addEventListener("click", async () => {
    status.replaceChildren();
    busy(step1, "Allowing…");
    try {
      // Must come first in the tap: iOS only asks for permission straight from a user gesture.
      const permission = await Notification.requestPermission();
      if (permission !== "granted") throw new Error(ios ? "Notifications are off for Locked. Turn them on in Settings → Notifications → Locked, then try again." : "Notifications are blocked for this site. Allow them in the browser's site settings, then try again.");
      subscription = await subscribe();
      begun = await api("POST", "pair/begin", { code: codeInput.value });
      codeInput.disabled = true;
      step1.replaceWith(step2);
      status.replaceChildren(h("p", { class: "muted" }, `Notifications are on. Now create the passkey: ${ios ? "Face ID saves it" : "the phone saves it"} for Locked, and it's what unlocks each credential later.`));
    } catch (e) {
      step1.disabled = false;
      step1.replaceChildren("Allow notifications");
      status.replaceChildren(errorBox(e.message));
    }
  });

  const step2 = h("button", { class: "btn btn-primary", type: "button" }, "Create passkey");
  step2.addEventListener("click", async () => {
    status.replaceChildren();
    const pk = begun.publicKey;
    let created;
    try {
      // Called straight from the tap: Safari wants a user gesture for passkeys too.
      created = navigator.credentials.create({
        publicKey: {
          ...pk,
          challenge: b64uDecode(pk.challenge),
          user: { ...pk.user, id: b64uDecode(pk.user.id) },
          excludeCredentials: pk.excludeCredentials.map((c) => ({ type: "public-key", id: b64uDecode(c.id) })),
        },
      });
      busy(step2, "Creating…");
      const cred = await created;
      const res = await api("POST", "pair/finish", {
        pairingId: begun.pairingId,
        name: nameInput.value,
        subscription: subscription.toJSON(),
        credential: { clientDataJSON: b64uEncode(cred.response.clientDataJSON), attestationObject: b64uEncode(cred.response.attestationObject) },
      });
      device.set({ id: res.deviceId, name: res.name });
      show(
        stateCard(
          `Paired as “${res.name}”`,
          res.pushOk
            ? "A first notification is on its way. Leave notifications on: your agent's credentials arrive the same way. You can close this now."
            : "Paired, but the first notification didn't go through. Check Settings → Notifications → Locked, then run `locked phone test` on the Mac.",
          res.pushOk ? "tone-ok" : "tone-warn",
        ),
      );
    } catch (e) {
      step2.disabled = false;
      step2.replaceChildren("Create passkey");
      const msg = e.name === "NotAllowedError" ? "The passkey wasn't created. Tap Create passkey to try again." : e.message;
      status.replaceChildren(errorBox(msg));
      if (e.code === "expired") {
        // The challenge ran out; the code still works until the pairing ends.
        codeInput.disabled = false;
        step2.replaceWith(step1);
        step1.disabled = false;
        step1.replaceChildren("Allow notifications");
      }
    }
  });
}

// --- a share ---

async function openEnvelope(env, privateKey, aad) {
  const peer = await subtle.importKey("raw", b64uDecode(env.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: b64uDecode(env.salt), info: enc.encode(PHONE_INFO) }, ikm, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: b64uDecode(env.iv), additionalData: enc.encode(aad) }, key, b64uDecode(env.ct));
  return JSON.parse(dec.decode(plain));
}

/** A fresh page key and server challenge, made before the tap so the tap can go straight to Face ID. */
async function prepareUnlock(token) {
  const [challenge, pair] = await Promise.all([
    api("POST", `s/${token}/challenge`),
    subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
  ]);
  return { challenge, pair, epk: b64uEncode(await subtle.exportKey("raw", pair.publicKey)), at: Date.now() };
}

async function shareView(token) {
  stopTimer();
  onVisible = null;
  clearInterval(refresher);
  show(h("section", { class: "card loading" }, h("p", {}, "Loading…")));
  let info;
  try {
    info = await api("GET", `s/${token}`);
  } catch (e) {
    return show(stateCard(e.status === 410 ? "This share has ended" : "Couldn't open it", e.status === 410 ? "It expired or was closed. Ask your agent to send it again." : e.message, "tone-warn"));
  }

  let session = null;
  let values = null;
  let ready = prepareUnlock(token);
  ready.catch(() => {});
  // Challenges last two minutes; keep a fresh one so a late tap still goes straight to Face ID.
  const keepReady = (on) => {
    clearInterval(refresher);
    if (on) refresher = setInterval(() => {
      ready = prepareUnlock(token);
      ready.catch(() => {});
    }, 90_000);
  };

  const send = (event, field) => session && api("POST", `s/${token}/event`, { session, event, field }).catch(() => {});
  const wipe = () => {
    if (values) for (const k of Object.keys(values)) values[k] = "";
    values = null;
  };
  const ended = (title, body) => {
    wipe();
    keepReady(false);
    onVisible = null;
    session = null;
    stopTimer();
    show(stateCard(title, body, "tone-ok"));
  };
  startTimer(info.expiresAt, () => ended("This share has ended", "The values are wiped from this phone."));

  const header = [
    h("p", { class: "eyebrow" }, "Your agent shared"),
    h("h1", { class: "title" }, info.label),
    info.site ? h("p", { class: "site-line" }, info.site) : null,
    info.purpose ? h("p", { class: "reason" }, `Agent: ${info.purpose}`) : null,
    info.level === "sealed" ? h("p", { class: "badge badge-sealed" }, "Sealed") : null,
  ];

  function locked(message) {
    const button = h("button", { class: "btn btn-primary", type: "button" }, `Unlock with ${ios ? "Face ID" : "passkey"}`);
    const status = h("div", { class: "pair-status" }, message ? errorBox(message) : null);
    const list = h("ul", { class: "share-fields" }, info.fields.map((f) => h("li", {}, h("span", { class: "share-name" }, f.label), h("span", { class: "dots", "aria-hidden": "true" }, "••••••••"))));
    show(h("section", { class: "card" }, ...header, list, status, h("div", { class: "actions" }, button)));
    keepReady(true);

    button.addEventListener("click", async () => {
      status.replaceChildren();
      let prep;
      try {
        prep = await ready;
        if (Date.now() - prep.at > 100_000) throw Object.assign(new Error("stale"), { stale: true });
      } catch (e) {
        ready = prepareUnlock(token);
        ready.catch(() => {});
        if (e.status === 410) return ended("This share has ended", "Ask your agent to send it again.");
        status.replaceChildren(e.stale ? h("p", { class: "muted" }, "Getting ready… tap Unlock again.") : errorBox(`${e.message} Tap Unlock to try again.`));
        return;
      }
      let asking;
      try {
        // Straight from the tap, without awaiting anything first: Safari wants a user gesture.
        asking = navigator.credentials.get({
          publicKey: {
            challenge: b64uDecode(prep.challenge.challenge),
            rpId: prep.challenge.rpId,
            allowCredentials: info.credentialIds.map((id) => ({ type: "public-key", id: b64uDecode(id) })),
            userVerification: "required",
            timeout: prep.challenge.timeoutMs,
          },
        });
        busy(button, "Unlocking…");
        const cred = await asking;
        const res = await api("POST", `s/${token}/unlock`, {
          epk: prep.epk,
          assertion: {
            credentialId: b64uEncode(cred.rawId),
            clientDataJSON: b64uEncode(cred.response.clientDataJSON),
            authenticatorData: b64uEncode(cred.response.authenticatorData),
            signature: b64uEncode(cred.response.signature),
            userHandle: cred.response.userHandle ? b64uEncode(cred.response.userHandle) : null,
          },
        });
        values = (await openEnvelope(res.envelope, prep.pair.privateKey, info.id)).values;
        session = res.session;
        keepReady(false);
        unlocked();
      } catch (e) {
        if (e.status === 410) return ended("This share has ended", "Ask your agent to send it again.");
        locked(e.name === "NotAllowedError" ? `${ios ? "Face ID" : "The passkey"} was cancelled. Tap Unlock to try again.` : e.message);
      } finally {
        // Each unlock spends its challenge; have the next one ready.
        ready = prepareUnlock(token);
        ready.catch(() => {});
      }
    });
  }

  function unlocked() {
    const toast = h("p", { class: "toast", role: "status", "aria-live": "polite" });
    const rows = info.fields.map((f) => {
      const value = h("output", { class: "value", hidden: true });
      const showBtn = h("button", { class: "btn btn-secondary btn-small", type: "button" }, "Show");
      const copyBtn = h("button", { class: "btn btn-primary btn-small", type: "button" }, "Copy");
      let shown = false;
      showBtn.addEventListener("click", () => {
        if (!values) return;
        shown = !shown;
        value.textContent = shown ? values[f.name] : "";
        value.hidden = !shown;
        showBtn.textContent = shown ? "Hide" : "Show";
        if (shown) send("shown", f.name);
      });
      copyBtn.addEventListener("click", async () => {
        if (!values) return;
        try {
          await navigator.clipboard.writeText(values[f.name]);
          toast.textContent = `${f.label} copied. Paste it where you need it${ios ? "" : "; clear the clipboard afterwards"}.`;
          send("copied", f.name);
        } catch {
          // No clipboard access: show it instead, selected, so it can be copied by hand.
          if (!shown) showBtn.click();
          toast.textContent = "Couldn't copy here: it's shown instead, so you can type or copy it.";
        }
      });
      return h(
        "li",
        { class: "share-row" },
        h("div", { class: "share-row-head" }, h("span", { class: "share-name" }, f.label), h("span", { class: "share-buttons" }, showBtn, copyBtn)),
        value,
      );
    });
    const done = h("button", { class: "btn btn-secondary", type: "button" }, "Done");
    done.addEventListener("click", () => {
      send("closed");
      ended("Done", "The values are wiped from this phone.");
    });
    show(h("section", { class: "card" }, ...header, h("ul", { class: "share-fields unlocked" }, rows), toast, h("div", { class: "actions" }, done)));
  }

  onVisible = (away) => {
    if (values && away > WIPE_AFTER_HIDDEN_MS) {
      wipe();
      locked(`Locked again after a while in the background. Unlock with ${ios ? "Face ID" : "the passkey"} to see it again.`);
    }
  };

  locked();
}

// --- home ---

async function recentShares() {
  try {
    const res = await (await caches.open("locked")).match("/phone/__shares");
    const list = res ? await res.json() : [];
    return list.filter((x) => x.exp > Date.now());
  } catch {
    return [];
  }
}

async function homeView() {
  stopTimer();
  onVisible = null;
  clearInterval(refresher);
  const d = device.get();
  if (!d) return pairView("");
  if (pushSupported) serviceWorker().catch(() => {});
  const shares = await recentShares();
  const permission = "Notification" in window ? Notification.permission : "default";
  show(
    h(
      "section",
      { class: "card" },
      h("p", { class: "eyebrow" }, "Paired"),
      h("h1", { class: "title" }, d.name),
      h("p", { class: "muted lead" }, "When your agent shares a credential with this phone, a notification arrives. Tap it to unlock."),
      permission !== "granted" ? errorBox(ios ? "Notifications are off: turn them on in Settings → Notifications → Locked." : "Notifications are off for this site.") : null,
    ),
    shares.length
      ? h(
          "section",
          { class: "card" },
          h("h2", { class: "section-title" }, "Open shares"),
          h("ul", { class: "share-list" }, shares.map((s) => h("li", {}, h("a", { href: `#s=${s.s}`, class: "share-link" }, h("strong", {}, s.title), h("span", { class: "muted" }, s.body))))),
        )
      : null,
    h("p", { class: "muted small" }, "Pair again: on the Mac, run locked phone pair and open its link here."),
  );
}

// --- routing ---

function route() {
  const params = new URLSearchParams(location.hash.slice(1));
  const share = params.get("s");
  const pair = params.get("pair");
  // Read once, then keep the token out of the address bar.
  if (location.hash) history.replaceState(null, "", location.pathname);
  if (share && /^[A-Za-z0-9_-]{20,64}$/.test(share)) return shareView(share);
  if (pair !== null) return pairView(pair);
  return homeView();
}

window.addEventListener("hashchange", route);
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.addEventListener("message", (event) => {
    if (event.data?.type === "open" && typeof event.data.url === "string") {
      const u = new URL(event.data.url);
      if (u.origin === location.origin) {
        history.replaceState(null, "", u.pathname + u.hash);
        route();
      }
    }
  });
}
route();
