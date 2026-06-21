import express from "express";
import path from "node:path";
import jose from "node-jose";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert";
import { db } from "./db";
import { clients, users } from "./db/schema";
import { eq } from "drizzle-orm";
import crypto from "crypto";
import type { JWTClaims } from "./utils/user-token";
import JWT from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT ?? 8000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.resolve("public")));

const ISSUER = `http://localhost:${PORT}`;
const AUTH_CODE_TTL_SECONDS = 300;
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;
const DEFAULT_SCOPE = "openid profile email";

type AuthCodeRecord = {
  userId: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  expiresAt: number;
};

type RefreshTokenRecord = {
  userId: string;
  clientId: string;
  scope: string;
  expiresAt: number;
};

const authCodes = new Map<string, AuthCodeRecord>();
const refreshTokens = new Map<string, RefreshTokenRecord>();

const oauthMetadata = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/o/authenticate`,
  token_endpoint: `${ISSUER}/o/token`,
  userinfo_endpoint: `${ISSUER}/o/userinfo`,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
  scopes_supported: ["openid", "profile", "email"],
  code_challenge_methods_supported: ["plain", "S256"],
};

function getQueryValue(value: unknown) {
  return typeof value === "string" ? value : undefined;
}

function buildRedirectUrl(
  redirectUri: string,
  params: Record<string, string | undefined>,
) {
  const url = new URL(redirectUri);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

function createAuthCode(record: Omit<AuthCodeRecord, "expiresAt">) {
  const code = crypto.randomBytes(32).toString("hex");
  authCodes.set(code, {
    ...record,
    expiresAt: Date.now() + AUTH_CODE_TTL_SECONDS * 1000,
  });
  return code;
}

function consumeAuthCode(code: string) {
  const record = authCodes.get(code);

  if (!record) {
    return undefined;
  }

  authCodes.delete(code);

  if (record.expiresAt < Date.now()) {
    return undefined;
  }

  return record;
}

function createRefreshToken(record: Omit<RefreshTokenRecord, "expiresAt">) {
  const refreshToken = crypto.randomBytes(32).toString("hex");
  refreshTokens.set(refreshToken, {
    ...record,
    expiresAt: Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000,
  });
  return refreshToken;
}

function consumeRefreshToken(refreshToken: string) {
  const record = refreshTokens.get(refreshToken);

  if (!record) {
    return undefined;
  }

  refreshTokens.delete(refreshToken);

  if (record.expiresAt < Date.now()) {
    return undefined;
  }

  return record;
}

function normalizeScope(scope?: string) {
  const value = scope?.trim();
  return value || DEFAULT_SCOPE;
}

function getClientCredentials(req: express.Request) {
  const body = req.body as Record<string, string | undefined>;
  const authHeader = req.headers.authorization;

  if (authHeader?.toLowerCase().startsWith("basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator !== -1) {
      return {
        clientId: decoded.slice(0, separator),
        clientSecret: decoded.slice(separator + 1),
      };
    }
  }

  return {
    clientId: body.client_id,
    clientSecret: body.client_secret,
  };
}

async function findClient(clientId?: string) {
  if (!clientId) return undefined;

  const [client] = await db
    .select()
    .from(clients)
    .where(eq(clients.clientId, clientId))
    .limit(1);

  return client;
}

function validateRedirectUri(
  client: Awaited<ReturnType<typeof findClient>>,
  redirectUri?: string,
) {
  return Boolean(client && redirectUri && redirectUri === client.redirectUri);
}

async function createUserTokens(
  user: typeof users.$inferSelect,
  options: {
    clientId?: string;
    nonce?: string;
    scope?: string;
  } = {},
) {
  const { clientId, nonce, scope = DEFAULT_SCOPE } = options;
  const now = Math.floor(Date.now() / 1000);

  const baseClaims = {
    iss: ISSUER,
    sub: user.id,
    aud: clientId,
    scope,
    email: user.email,
    email_verified: user.emailVerified,
    iat: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS,
    given_name: user.firstName ?? "",
    family_name: user.lastName ?? undefined,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL ?? undefined,
  };

  const idTokenClaims: JWTClaims = {
    ...baseClaims,
    nonce,
  };

  const accessTokenClaims: JWTClaims = {
    ...baseClaims,
  };

  const idToken = JWT.sign(idTokenClaims, PRIVATE_KEY, { algorithm: "RS256" });
  const accessToken = JWT.sign(accessTokenClaims, PRIVATE_KEY, {
    algorithm: "RS256",
  });

  return { idToken, accessToken };
}

async function issueTokenResponse(
  user: typeof users.$inferSelect,
  client: NonNullable<Awaited<ReturnType<typeof findClient>>>,
  options: {
    nonce?: string;
    scope?: string;
  } = {},
) {
  const scope = normalizeScope(options.scope);
  const { idToken, accessToken } = await createUserTokens(user, {
    clientId: client.clientId,
    nonce: options.nonce,
    scope,
  });
  const refreshToken = createRefreshToken({
    userId: user.id,
    clientId: client.clientId,
    scope,
  });

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope,
    id_token: idToken,
  };
}

async function handleAuthorize(req: express.Request, res: express.Response) {
  const clientId = getQueryValue(req.query.client_id);
  const redirectUri = getQueryValue(req.query.redirect_uri);
  const responseType = getQueryValue(req.query.response_type) ?? "code";
  const client = await findClient(clientId);

  if (!client) {
    res.status(400).send("Missing or invalid client_id.");
    return;
  }

  if (!validateRedirectUri(client, redirectUri)) {
    res.status(400).send("Missing or invalid redirect_uri.");
    return;
  }

  if (responseType !== "code") {
    res.status(400).send("Unsupported response_type.");
    return;
  }

  return res.sendFile(path.resolve("public", "authenticate.html"));
}

async function handleToken(req: express.Request, res: express.Response) {
  const body = req.body as Record<string, string | undefined>;
  const { grant_type, code, redirect_uri, refresh_token, nonce } = body;
  const { clientId, clientSecret } = getClientCredentials(req);

  if (!grant_type || !clientId || !clientSecret) {
    res.status(400).json({ message: "Missing required token request fields." });
    return;
  }

  const client = await findClient(clientId);

  if (!client || client.clientSecret !== clientSecret) {
    res.status(401).json({ message: "Invalid client credentials." });
    return;
  }

  if (grant_type === "authorization_code") {
    if (!code || !redirect_uri) {
      res.status(400).json({ message: "Missing authorization code or redirect URI." });
      return;
    }

    const authCode = consumeAuthCode(code);

    if (
      !authCode ||
      authCode.clientId !== client.clientId ||
      authCode.redirectUri !== redirect_uri
    ) {
      res.status(400).json({ message: "Invalid or expired authorization code." });
      return;
    }

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, authCode.userId))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    res.json(
      await issueTokenResponse(user, client, {
        nonce: authCode.nonce ?? nonce,
        scope: authCode.scope,
      }),
    );
    return;
  }

  if (grant_type === "refresh_token") {
    if (!refresh_token) {
      res.status(400).json({ message: "Missing refresh_token." });
      return;
    }

    const storedRefreshToken = consumeRefreshToken(refresh_token);

    if (!storedRefreshToken || storedRefreshToken.clientId !== client.clientId) {
      res.status(400).json({ message: "Invalid or expired refresh token." });
      return;
    }

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, storedRefreshToken.userId))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    res.json(
      await issueTokenResponse(user, client, {
        scope: storedRefreshToken.scope,
      }),
    );
    return;
  }

  res.status(400).json({ message: "Unsupported grant_type." });
}

app.get("/", (req, res) => res.json({ message: "Hello from Auth Server" }));
app.get("/health", (req, res) =>
  res.json({ message: "Server is healthy", healthy: true }),
);

app.get("/admin/applications", (_, res) => {
  res.redirect("/admin-applications.html");
});

app.post("/admin/applications", async (req, res) => {
  const { displayName, applicationUrl, redirectUri } = req.body;

  if (!displayName || !applicationUrl || !redirectUri) {
    res.status(400).json({ message: "All application fields are required." });
    return;
  }

  const clientId = crypto.randomBytes(16).toString("hex");
  const clientSecret = crypto.randomBytes(32).toString("hex");

  await db.insert(clients).values({
    displayName,
    applicationUrl,
    redirectUri,
    clientId,
    clientSecret,
  });

  res.status(201).json({ clientId, clientSecret });
});

// OIDC / OAuth endpoints
app.get("/.well-known/openid-configuration", (_, res) => {
  return res.json({
    ...oauthMetadata,
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
});

app.get("/.well-known/oauth-authorization-server", (_, res) => {
  return res.json(oauthMetadata);
});

app.get("/.well-known/jwks.json", async (_, res) => {
  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
  return res.json({ keys: [key.toJSON()] });
});

app.get("/o/authenticate", handleAuthorize);
app.get("/oauth/authorize", handleAuthorize);

app.post("/o/authenticate/sign-in", async (req, res) => {
  const { email, password, client_id, redirect_uri, state, nonce, scope } =
    req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required." });
    return;
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (!user || !user.password || !user.salt) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const hash = crypto
    .createHash("sha256")
    .update(password + user.salt)
    .digest("hex");

  if (hash !== user.password) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const client = await findClient(client_id);

  if (client_id && redirect_uri) {
    if (!validateRedirectUri(client, redirect_uri)) {
      res.status(400).json({ message: "Invalid client or redirect URI." });
      return;
    }

    const code = createAuthCode({
      userId: user.id,
      clientId: client!.clientId,
      redirectUri: redirect_uri,
      scope: normalizeScope(scope),
      nonce,
    });

    res.json({
      redirect: buildRedirectUrl(redirect_uri, { code, state }),
    });
    return;
  }

  const { accessToken } = await createUserTokens(user);
  res.json({ token: accessToken });
});

app.post("/o/token", handleToken);
app.post("/oauth/token", handleToken);

app.post("/o/authenticate/sign-up", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!email || !password || !firstName) {
    res
      .status(400)
      .json({ message: "First name, email, and password are required" });
    return;
  }

  const [existing] = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (existing) {
    res
      .status(409)
      .json({ message: "An account with this email already exists." });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest("hex");

  await db.insert(users).values({
    firstName,
    lastName: lastName ?? null,
    email,
    password: hash,
    salt,
  });
  res.status(201).json({ ok: true });
});

app.get("/o/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.toLowerCase().startsWith("bearer ")) {
    res
      .status(401)
      .json({ message: "Missing or invalid Authorization header." });
    return;
  }
  const token = authHeader.slice(7);
  let claims: JWTClaims;
  try {
    claims = JWT.verify(token, PUBLIC_KEY, {
      algorithms: ["RS256"],
    }) as JWTClaims;
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, claims.sub))
    .limit(1);
  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    given_name: user.firstName,
    family_name: user.lastName,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL,
  });
});

app.listen(PORT, () => {
  console.log(`AuthServer is running on PORT ${PORT}`);
});
