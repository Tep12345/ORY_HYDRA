import crypto from "node:crypto";
import express from "express";
import session from "express-session";

const authUiPort = Number(process.env.AUTH_UI_PORT ?? 3000);
const clientPort = Number(process.env.CLIENT_PORT ?? 3001);
const hydraAdminUrl = process.env.HYDRA_ADMIN_URL ?? "http://localhost:4445";
const hydraPublicUrl = process.env.HYDRA_PUBLIC_URL ?? "http://localhost:4444";
const hydraPublicInternalUrl =
  process.env.HYDRA_PUBLIC_INTERNAL_URL ?? hydraPublicUrl;
const oauthClientId = process.env.OAUTH_CLIENT_ID ?? "demo-client";
const oauthClientSecret = process.env.OAUTH_CLIENT_SECRET ?? "demo-secret";
const oauthRedirectUri =
  process.env.OAUTH_REDIRECT_URI ?? "http://localhost:3001/callback";
const sessionSecret = process.env.SESSION_SECRET ?? "dev-session-secret";

const users = new Map([
  [
    "alice@example.com",
    {
      id: "user-alice",
      email: "alice@example.com",
      name: "Alice Example",
      password: "password"
    }
  ]
]);

function createApp(name) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(
    session({
      name,
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false
      }
    })
  );
  return app;
}

async function hydraAdmin(path, options = {}) {
  const response = await fetch(`${hydraAdminUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {})
    }
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Hydra admin ${path} failed: ${response.status} ${body}`);
  }

  return response.json();
}

async function ensureOAuthClient() {
  console.log(`Using Hydra admin endpoint ${hydraAdminUrl}`);

  let existing;
  for (let attempt = 1; attempt <= 20; attempt += 1) {
    try {
      existing = await fetch(
        `${hydraAdminUrl}/admin/clients/${encodeURIComponent(oauthClientId)}`
      );
      break;
    } catch (error) {
      if (attempt === 20) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  if (existing.ok) {
    return;
  }

  if (existing.status !== 404) {
    throw new Error(
      `OAuth client lookup failed: ${existing.status} ${await existing.text()}`
    );
  }

  await hydraAdmin("/admin/clients", {
    method: "POST",
    body: JSON.stringify({
      client_id: oauthClientId,
      client_secret: oauthClientSecret,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: [oauthRedirectUri],
      scope: "openid profile email offline_access",
      token_endpoint_auth_method: "client_secret_basic"
    })
  });
}

function page(title, body) {
  return `<!doctype html>
<html lang="ja">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        color-scheme: light;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f7f8fb;
        color: #17202a;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
      }
      main {
        width: min(92vw, 520px);
        background: #ffffff;
        border: 1px solid #dde3ea;
        border-radius: 8px;
        padding: 28px;
        box-shadow: 0 18px 44px rgba(39, 52, 67, 0.12);
      }
      h1 {
        margin: 0 0 18px;
        font-size: 24px;
        line-height: 1.2;
      }
      label {
        display: grid;
        gap: 6px;
        margin: 14px 0;
        font-size: 14px;
        font-weight: 650;
      }
      input {
        border: 1px solid #c8d1dc;
        border-radius: 6px;
        font: inherit;
        padding: 11px 12px;
      }
      button, .button {
        display: inline-flex;
        justify-content: center;
        align-items: center;
        min-height: 42px;
        border: 0;
        border-radius: 6px;
        background: #1769aa;
        color: white;
        font: inherit;
        font-weight: 700;
        padding: 0 16px;
        text-decoration: none;
        cursor: pointer;
      }
      .secondary {
        background: #4b5968;
      }
      .danger {
        background: #b3261e;
      }
      .actions {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 20px;
      }
      .notice {
        background: #eef6ff;
        border: 1px solid #c8e1ff;
        border-radius: 6px;
        padding: 12px;
      }
      .error {
        background: #fff1f0;
        border-color: #ffd4d0;
      }
      pre {
        overflow: auto;
        background: #111827;
        color: #f9fafb;
        border-radius: 6px;
        padding: 14px;
        white-space: pre-wrap;
        word-break: break-word;
      }
      dl {
        display: grid;
        grid-template-columns: max-content 1fr;
        gap: 8px 12px;
      }
      dt {
        font-weight: 700;
      }
      dd {
        margin: 0;
      }
    </style>
  </head>
  <body>
    <main>${body}</main>
  </body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function decodeJwt(token) {
  if (!token) {
    return null;
  }

  const [, payload] = token.split(".");
  if (!payload) {
    return null;
  }
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

const authUi = createApp("auth-ui.sid");

authUi.get("/login", async (req, res, next) => {
  try {
    const challenge = req.query.login_challenge;
    if (!challenge) {
      res.status(400).send("missing login_challenge");
      return;
    }

    const loginRequest = await hydraAdmin(
      `/admin/oauth2/auth/requests/login?login_challenge=${encodeURIComponent(challenge)}`
    );

    if (loginRequest.skip && req.session.user) {
      const accepted = await hydraAdmin(
        `/admin/oauth2/auth/requests/login/accept?login_challenge=${encodeURIComponent(challenge)}`,
        {
          method: "PUT",
          body: JSON.stringify({
            subject: req.session.user.id,
            remember: true,
            remember_for: 3600
          })
        }
      );
      res.redirect(accepted.redirect_to);
      return;
    }

    const error = req.query.error
      ? `<p class="notice error">${escapeHtml(req.query.error)}</p>`
      : "";

    res.send(
      page(
        "Login",
        `<h1>ログイン</h1>
        ${error}
        <p class="notice">デモユーザー: alice@example.com / password</p>
        <form method="post" action="/login">
          <input type="hidden" name="login_challenge" value="${escapeHtml(challenge)}">
          <label>メールアドレス
            <input name="email" type="email" autocomplete="email" value="alice@example.com" required>
          </label>
          <label>パスワード
            <input name="password" type="password" autocomplete="current-password" value="password" required>
          </label>
          <div class="actions">
            <button type="submit">ログイン</button>
          </div>
        </form>`
      )
    );
  } catch (error) {
    next(error);
  }
});

authUi.post("/login", async (req, res, next) => {
  try {
    const { login_challenge: challenge, email, password } = req.body;
    const user = users.get(email);

    if (!user || user.password !== password) {
      res.redirect(
        `/login?login_challenge=${encodeURIComponent(challenge)}&error=${encodeURIComponent("メールアドレスまたはパスワードが違います")}`
      );
      return;
    }

    req.session.user = { id: user.id, email: user.email, name: user.name };

    const accepted = await hydraAdmin(
      `/admin/oauth2/auth/requests/login/accept?login_challenge=${encodeURIComponent(challenge)}`,
      {
        method: "PUT",
        body: JSON.stringify({
          subject: user.id,
          remember: true,
          remember_for: 3600
        })
      }
    );

    res.redirect(accepted.redirect_to);
  } catch (error) {
    next(error);
  }
});

authUi.get("/consent", async (req, res, next) => {
  try {
    const challenge = req.query.consent_challenge;
    if (!challenge) {
      res.status(400).send("missing consent_challenge");
      return;
    }

    const consentRequest = await hydraAdmin(
      `/admin/oauth2/auth/requests/consent?consent_challenge=${encodeURIComponent(challenge)}`
    );

    if (consentRequest.skip) {
      const accepted = await acceptConsent(challenge, consentRequest);
      res.redirect(accepted.redirect_to);
      return;
    }

    const scopes = consentRequest.requested_scope ?? [];
    const scopeInputs = scopes
      .map(
        (scope) =>
          `<label><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> ${escapeHtml(scope)}</label>`
      )
      .join("");

    res.send(
      page(
        "Consent",
        `<h1>アクセス許可</h1>
        <dl>
          <dt>Client</dt><dd>${escapeHtml(consentRequest.client?.client_id ?? "unknown")}</dd>
          <dt>Subject</dt><dd>${escapeHtml(consentRequest.subject)}</dd>
        </dl>
        <form method="post" action="/consent">
          <input type="hidden" name="consent_challenge" value="${escapeHtml(challenge)}">
          ${scopeInputs}
          <div class="actions">
            <button type="submit">許可</button>
            <button class="danger" type="submit" formaction="/consent/reject">拒否</button>
          </div>
        </form>`
      )
    );
  } catch (error) {
    next(error);
  }
});

authUi.post("/consent", async (req, res, next) => {
  try {
    const challenge = req.body.consent_challenge;
    const consentRequest = await hydraAdmin(
      `/admin/oauth2/auth/requests/consent?consent_challenge=${encodeURIComponent(challenge)}`
    );
    const accepted = await acceptConsent(challenge, consentRequest, req.body.scope);
    res.redirect(accepted.redirect_to);
  } catch (error) {
    next(error);
  }
});

authUi.post("/consent/reject", async (req, res, next) => {
  try {
    const challenge = req.body.consent_challenge;
    const rejected = await hydraAdmin(
      `/admin/oauth2/auth/requests/consent/reject?consent_challenge=${encodeURIComponent(challenge)}`,
      {
        method: "PUT",
        body: JSON.stringify({
          error: "access_denied",
          error_description: "The user denied the request."
        })
      }
    );
    res.redirect(rejected.redirect_to);
  } catch (error) {
    next(error);
  }
});

authUi.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.send(page("Logout", `<h1>ログアウトしました</h1>`));
  });
});

authUi.use((error, _req, res, _next) => {
  console.error(error);
  res
    .status(500)
    .send(page("Error", `<h1>エラー</h1><pre>${escapeHtml(error.message)}</pre>`));
});

async function acceptConsent(challenge, consentRequest, selectedScope) {
  const grantedScope = Array.isArray(selectedScope)
    ? selectedScope
    : selectedScope
      ? [selectedScope]
      : consentRequest.requested_scope ?? [];

  const user = [...users.values()].find((entry) => entry.id === consentRequest.subject);
  const sessionClaims = {
    id_token: {
      email: user?.email,
      name: user?.name
    },
    access_token: {
      email: user?.email,
      name: user?.name
    }
  };

  return hydraAdmin(
    `/admin/oauth2/auth/requests/consent/accept?consent_challenge=${encodeURIComponent(challenge)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        grant_scope: grantedScope,
        grant_access_token_audience: consentRequest.requested_access_token_audience ?? [],
        remember: true,
        remember_for: 3600,
        session: sessionClaims
      })
    }
  );
}

const client = createApp("sample-client.sid");

client.get("/", (req, res) => {
  const tokenBlock = req.session.tokens
    ? `<h1>認証済み</h1>
      <p class="notice">Hydra からトークンを取得しました。</p>
      <h2>ID Token claims</h2>
      <pre>${escapeHtml(JSON.stringify(decodeJwt(req.session.tokens.id_token), null, 2))}</pre>
      <h2>Token response</h2>
      <pre>${escapeHtml(JSON.stringify(req.session.tokens, null, 2))}</pre>
      <div class="actions"><a class="button secondary" href="/clear">セッションを消す</a></div>`
    : `<h1>サンプルクライアント</h1>
      <p class="notice">Authorization Code flow で Hydra にリダイレクトします。</p>
      <div class="actions"><a class="button" href="/start">ログインして開始</a></div>`;

  res.send(page("Sample Client", tokenBlock));
});

client.get("/start", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.oauthNonce = nonce;

  const params = new URLSearchParams({
    client_id: oauthClientId,
    redirect_uri: oauthRedirectUri,
    response_type: "code",
    scope: "openid profile email offline_access",
    state,
    nonce
  });

  res.redirect(`${hydraPublicUrl}/oauth2/auth?${params.toString()}`);
});

client.get("/callback", async (req, res, next) => {
  try {
    if (req.query.state !== req.session.oauthState) {
      res.status(400).send("invalid state");
      return;
    }

    const credentials = Buffer.from(
      `${oauthClientId}:${oauthClientSecret}`,
      "utf8"
    ).toString("base64");
    const response = await fetch(`${hydraPublicInternalUrl}/oauth2/token`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: req.query.code,
        redirect_uri: oauthRedirectUri
      })
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status} ${await response.text()}`);
    }

    req.session.tokens = await response.json();
    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

client.get("/clear", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

client.use((error, _req, res, _next) => {
  console.error(error);
  res
    .status(500)
    .send(page("Error", `<h1>エラー</h1><pre>${escapeHtml(error.message)}</pre>`));
});

await ensureOAuthClient();

authUi.listen(authUiPort, () => {
  console.log(`Auth UI listening on http://localhost:${authUiPort}`);
});

client.listen(clientPort, () => {
  console.log(`Sample client listening on http://localhost:${clientPort}`);
});
