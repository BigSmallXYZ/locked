// The CSP hop. A page whose CSP blocks the autofill fetch navigates here with
//   #t=<one-time token>&k=<AES-GCM key made in that page>&r=<page URL>
// We fetch the values from our own origin, encrypt them with that key and go straight back to
// the page with only the ciphertext in its fragment: r#locked=<base64url(iv || ciphertext)>.
// The server only answers when r is on the origin the secret is bound to. The key never leaves
// the browser; the snippet, run again on the page, decrypts and fills.

const status = document.getElementById("status");
const detail = document.getElementById("detail");

function show(title, body) {
  status.textContent = title;
  detail.textContent = body;
}

const b64u = {
  encode(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(text) {
    const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};

async function hop() {
  const params = new URLSearchParams(location.hash.slice(1));
  // Take the token and key out of the address bar and history before anything else.
  history.replaceState(null, "", location.pathname);
  const token = params.get("t");
  const key = params.get("k");
  const ret = params.get("r");
  if (!token || !key || !ret) return show("Nothing to do here", "This page only works as part of Locked's autofill.");

  let back;
  try {
    back = new URL(ret);
    if (back.protocol !== "https:" && back.protocol !== "http:") throw new Error();
  } catch {
    return show("Can't go back", "The page address Locked was given isn't valid.");
  }

  let body;
  try {
    const res = await fetch(`/u/${encodeURIComponent(token)}/hop`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ return: back.href }),
      cache: "no-store",
      credentials: "omit",
    });
    body = await res.json();
  } catch {
    body = { ok: false, error: "error" };
  }

  if (!body?.ok) {
    // An origin mismatch means someone tried to send the values to the wrong site: stop here.
    if (body?.error === "origin") return show("Not sent", `Locked won't fill this secret into ${back.origin}.`);
    back.hash = "locked-error=" + (/^(missing|used|expired|rate)$/.test(body?.error) ? body.error : "error");
    return location.replace(back.href);
  }

  const aes = await crypto.subtle.importKey("raw", b64u.decode(key), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, new TextEncoder().encode(JSON.stringify(body))));
  body = null;
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv);
  blob.set(ct, iv.length);
  back.hash = "locked=" + b64u.encode(blob);
  location.replace(back.href);
}

hop().catch(() => show("Something went wrong", "Go back to the page and ask your agent to try again."));
