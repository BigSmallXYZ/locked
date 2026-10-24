// Login pages for trying the autofill snippet by hand or from test/autofill.e2e.ts.
//   bun test/fixtures/serve.ts          (http://127.0.0.1:7420, or $LOCKED_FIXTURE_PORT)
// Every page shows only the LENGTHS of what was submitted, never the values, and no
// form ever navigates.

const REACT = "https://unpkg.com/react@18.3.1/umd/react.production.min.js";
const REACT_DOM = "https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js";

export const FIXTURE_PAGES = ["/plain", "/react", "/two-step", "/csp", "/otp", "/shadow", "/iframe", "/apikey", "/signup"] as const;

const style = `
  :root { color-scheme: light dark; --bg: #fafaf9; --fg: #1c1917; --muted: #78716c; --line: #d6d3d1; --accent: #2563eb; }
  @media (prefers-color-scheme: dark) { :root { --bg: #1c1917; --fg: #f5f5f4; --muted: #a8a29e; --line: #44403c; --accent: #60a5fa; } }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px 16px; font: 15px/1.5 system-ui, sans-serif; background: var(--bg); color: var(--fg); }
  main { max-width: 420px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  p.note { color: var(--muted); margin: 0 0 20px; }
  form { display: grid; gap: 10px; }
  label { display: grid; gap: 4px; font-size: 13px; color: var(--muted); }
  input, textarea { font: inherit; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; background: transparent; color: var(--fg); width: 100%; }
  button { font: inherit; padding: 8px 14px; border: 0; border-radius: 6px; background: var(--accent); color: white; cursor: pointer; }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .otp { display: flex; gap: 8px; }
  .otp input { width: 44px; text-align: center; font-size: 20px; }
  #result, .result { margin-top: 16px; padding: 10px; border-radius: 6px; border: 1px dashed var(--line); min-height: 1.5em; }
  .hp { position: absolute; left: -9999px; top: 0; }
  nav { margin-bottom: 20px; font-size: 13px; } nav a { color: var(--accent); }
  footer { margin-top: 40px; display: grid; gap: 6px; }
`;

// Shared by every page: "username: 9 chars, password: 13 chars" from the inputs marked data-report.
const reportJs = `
  function lengths(root) {
    return Array.from(root.querySelectorAll("[data-report]"))
      .map(function (el) { return el.dataset.report + ": " + el.value.length + " chars"; })
      .join(", ");
  }
  function report(form, out) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      out.textContent = lengths(form);
      out.dataset.submitted = "1";
    });
  }
`;

function page(title: string, body: string, opts: { head?: string; nav?: boolean } = {}): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${style}</style>
<script>${reportJs}</script>
${opts.head ?? ""}
</head>
<body>
<main>
${opts.nav === false ? "" : `<nav><a href="/">All fixtures</a></nav>`}
${body}
</main>
</body>
</html>`;
}

// A login form with no autocomplete hints, plus things the snippet must leave alone:
// an off-screen honeypot, a hidden field, a search box and a newsletter email box.
const plainForm = `
<form id="login" action="/never" method="post">
  <label for="login-id">Email or username</label>
  <input id="login-id" name="login" type="text" data-report="username">
  <input class="hp" type="text" name="website" tabindex="-1" aria-hidden="true">
  <input type="hidden" name="csrf" value="fixture-csrf">
  <label for="pw">Password</label>
  <input id="pw" name="pass" type="password" data-report="password">
  <button type="submit">Sign in</button>
</form>
<div id="result" role="status"></div>
<footer>
  <form role="search"><input type="search" name="q" placeholder="Search the docs"></form>
  <form id="newsletter"><input type="email" name="newsletter" placeholder="Email me product updates"></form>
</footer>
<script>report(document.getElementById("login"), document.getElementById("result"));</script>`;

const pages: Record<string, () => string> = {
  "/": () =>
    page(
      "Locked fixtures",
      `<h1>Locked autofill fixtures</h1>
<p class="note">Login pages for the autofill snippet. Each shows only the lengths of what it receives.</p>
<ul>
  <li><a href="/plain">/plain</a>: plain form, no autocomplete hints, with a honeypot and decoys</li>
  <li><a href="/react">/react</a>: React 18 controlled inputs, submit enabled only when both are set</li>
  <li><a href="/two-step">/two-step</a>: email, Next, then a password step rendered by script</li>
  <li><a href="/csp">/csp</a>: like /plain, served with <code>Content-Security-Policy: connect-src 'self'</code></li>
  <li><a href="/otp">/otp</a>: six one-character code boxes</li>
  <li><a href="/shadow">/shadow</a>: form inside an open shadow root</li>
  <li><a href="/iframe">/iframe</a>: form inside a same-origin iframe</li>
  <li><a href="/apikey">/apikey</a>: settings page with an API key and a webhook URL</li>
  <li><a href="/signup">/signup</a>: new password plus a confirm box, no autocomplete hints</li>
</ul>`,
      { nav: false },
    ),

  "/plain": () => page("Plain login", `<h1>Sign in</h1><p class="note">A plain HTML form.</p>${plainForm}`),

  "/csp": () => page("CSP login", `<h1>Sign in</h1><p class="note">Served with connect-src 'self'.</p>${plainForm}`),

  "/embed/login": () => page("Embedded login", `<h1>Embedded sign in</h1>${plainForm}`, { nav: false }),

  "/iframe": () =>
    page(
      "Iframe login",
      `<h1>Sign in</h1>
<p class="note">The form lives in a same-origin iframe.</p>
<iframe id="frame" src="/embed/login" title="Sign in" style="width:100%;height:460px;border:1px solid var(--line);border-radius:8px"></iframe>`,
    ),

  "/react": () =>
    page(
      "React login",
      `<h1>Sign in</h1>
<p class="note">React 18 controlled inputs. The button stays disabled until React state has both values.</p>
<div id="root">Loading React…</div>
<script>
  (function () {
    var root = document.getElementById("root");
    if (!window.React || !window.ReactDOM) {
      root.textContent = "React did not load (offline?).";
      root.dataset.failed = "1";
      return;
    }
    var h = React.createElement;
    function App() {
      var u = React.useState(""), p = React.useState(""), done = React.useState("");
      var username = u[0], password = p[0];
      return h("div", null,
        h("form", {
          id: "login",
          onSubmit: function (e) {
            e.preventDefault();
            done[1]("username: " + username.length + " chars, password: " + password.length + " chars");
          }
        },
          h("label", null, "Username",
            h("input", { name: "username", autoComplete: "username", value: username, onChange: function (e) { u[1](e.target.value); } })),
          h("label", null, "Password",
            h("input", { name: "password", type: "password", autoComplete: "current-password", value: password, onChange: function (e) { p[1](e.target.value); } })),
          h("button", { type: "submit", id: "submit", disabled: !username || !password }, "Sign in")
        ),
        h("p", { id: "state" }, "React state: username " + username.length + " chars, password " + password.length + " chars"),
        h("div", { id: "result", role: "status", "data-submitted": done[0] ? "1" : undefined }, done[0])
      );
    }
    ReactDOM.createRoot(root).render(h(App));
    root.dataset.ready = "1";
  })();
</script>`,
      { head: `<script src="${REACT}" crossorigin></script>\n<script src="${REACT_DOM}" crossorigin></script>` },
    ),

  "/two-step": () =>
    page(
      "Two-step login",
      `<h1>Sign in</h1>
<p class="note">Email first; the password step is rendered by script, like Google.</p>
<div id="app"></div>
<div id="result" role="status"></div>
<script>
  (function () {
    var app = document.getElementById("app"), out = document.getElementById("result"), email = "";
    function stepOne() {
      app.innerHTML =
        '<form id="step1"><label for="identifierId">Email or phone</label>' +
        '<input id="identifierId" type="email" name="identifier" autocomplete="username">' +
        '<button type="submit" id="next">Next</button></form>';
      document.getElementById("step1").addEventListener("submit", function (e) {
        e.preventDefault();
        email = document.getElementById("identifierId").value;
        if (!email) return;
        app.innerHTML = '<p class="note">Checking…</p>';
        setTimeout(stepTwo, 300);
      });
    }
    function stepTwo() {
      app.innerHTML =
        '<form id="step2"><p class="note" id="who"></p>' +
        '<input type="email" name="identifier" autocomplete="username" hidden>' +
        '<input type="password" name="Passwd" autocomplete="current-password" aria-label="Enter your password">' +
        '<button type="submit">Next</button></form>';
      document.getElementById("who").textContent = "Account: " + email.length + " chars";
      var form = document.getElementById("step2");
      form.querySelector("input[hidden]").value = email;
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var pw = form.querySelector("input[type=password]").value;
        out.textContent = "email: " + email.length + " chars, password: " + pw.length + " chars";
        out.dataset.submitted = "1";
      });
    }
    stepOne();
  })();
</script>`,
    ),

  "/otp": () =>
    page(
      "One-time code",
      `<h1>Enter your code</h1>
<p class="note">Six boxes that take one digit each and move focus along.</p>
<form id="otp">
  <div class="otp">
    <input inputmode="numeric" maxlength="1" autocomplete="one-time-code" aria-label="Digit 1">
    <input inputmode="numeric" maxlength="1" aria-label="Digit 2">
    <input inputmode="numeric" maxlength="1" aria-label="Digit 3">
    <input inputmode="numeric" maxlength="1" aria-label="Digit 4">
    <input inputmode="numeric" maxlength="1" aria-label="Digit 5">
    <input inputmode="numeric" maxlength="1" aria-label="Digit 6">
  </div>
  <button type="submit">Verify</button>
</form>
<div id="result" role="status"></div>
<script>
  (function () {
    var form = document.getElementById("otp"), boxes = Array.from(form.querySelectorAll(".otp input"));
    boxes.forEach(function (box, i) {
      box.addEventListener("input", function () {
        box.value = box.value.replace(/\\D/g, "").slice(-1);
        if (box.value && boxes[i + 1]) boxes[i + 1].focus();
      });
    });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var code = boxes.map(function (b) { return b.value; }).join("");
      var out = document.getElementById("result");
      out.textContent = "code: " + code.length + " chars";
      out.dataset.submitted = "1";
    });
  })();
</script>`,
    ),

  "/shadow": () =>
    page(
      "Shadow DOM login",
      `<h1>Sign in</h1>
<p class="note">The form is inside an open shadow root.</p>
<login-card></login-card>
<div id="result" role="status"></div>
<script>
  customElements.define("login-card", class extends HTMLElement {
    constructor() {
      super();
      var root = this.attachShadow({ mode: "open" });
      root.innerHTML =
        '<style>form{display:grid;gap:10px}label{display:grid;gap:4px;font-size:13px}input{font:inherit;padding:8px}</style>' +
        '<form><label>Username <input name="user" autocomplete="username" data-report="username"></label>' +
        '<label>Password <input type="password" name="password" data-report="password"></label>' +
        '<button type="submit">Log in</button></form>';
      report(root.querySelector("form"), document.getElementById("result"));
    }
  });
</script>`,
    ),

  "/signup": () =>
    page(
      "Sign up",
      `<h1>Create an account</h1>
<p class="note">No autocomplete hints; the confirm box should get the new password too.</p>
<form id="signup">
  <label for="full">Full name</label>
  <input id="full" name="fullname" type="text">
  <label for="mail">Email</label>
  <input id="mail" name="email" type="email" data-report="email">
  <label for="np">Password</label>
  <input id="np" name="password" type="password" data-report="password">
  <label for="np2">Confirm password</label>
  <input id="np2" name="password2" type="password" data-report="confirm">
  <button type="submit">Create account</button>
</form>
<div id="result" role="status"></div>
<script>report(document.getElementById("signup"), document.getElementById("result"));</script>`,
    ),

  "/apikey": () =>
    page(
      "API settings",
      `<h1>Integration settings</h1>
<p class="note">Fields that are neither usernames nor passwords.</p>
<form id="settings">
  <label for="key">API key</label>
  <input id="key" name="apiKey" type="password" autocomplete="off" data-report="api key">
  <label for="hook">Webhook URL</label>
  <input id="hook" name="webhook_url" type="url" data-report="webhook">
  <label for="notes">Notes</label>
  <textarea id="notes" name="notes"></textarea>
  <button type="submit">Save</button>
</form>
<div id="result" role="status"></div>
<script>report(document.getElementById("settings"), document.getElementById("result"));</script>`,
    ),
};

export function startFixtureServer(port = Number(process.env.LOCKED_FIXTURE_PORT ?? 7420)) {
  return Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch(req) {
      const { pathname } = new URL(req.url);
      const render = pages[pathname];
      if (!render) return new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });
      const headers: Record<string, string> = { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" };
      if (pathname === "/csp") headers["content-security-policy"] = "connect-src 'self'";
      return new Response(render(), { headers });
    },
  });
}

if (import.meta.main) {
  const server = startFixtureServer();
  console.log(`Locked autofill fixtures on http://127.0.0.1:${server.port}/`);
}
