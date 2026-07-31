const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { Readable } = require("stream");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const { loadEnv } = require("./env");
const { sendWelcomeEmail, sendEmailCode } = require("./mailer");

loadEnv();

const {
  initializeStore,
  isSupabaseEnabled,
  isHostedWithoutSupabase,
  listUsers,
  saveUsers,
  deleteUserById,
  listMods,
  saveMods,
  deleteModById,
  listGames,
  saveGames,
  listReports,
  saveReports,
  listActivity,
  saveActivity,
  getEmailChallenge,
  saveEmailChallenge,
  deleteEmailChallenge,
  uploadModFile,
  createSignedModUpload,
  createSignedAssetUpload,
  deleteModFile,
  getModDownloadUrl,
  getModPreviewUrl,
} = require("./store");

const storeReady = initializeStore();

const app = express();
const port = process.env.PORT || 3000;
const uploadsDir = path.join(__dirname, "..", "uploads");
const sessionSecret = (process.env.SESSION_SECRET || "").trim() || crypto.randomBytes(32).toString("hex");
const rateLimitBuckets = new Map();

if (process.env.VERCEL && !(process.env.SESSION_SECRET || "").trim()) {
  throw new Error("SESSION_SECRET must be configured on Vercel.");
}

app.disable("x-powered-by");
app.set("trust proxy", 1);

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown")
    .split(",")[0]
    .trim();
}

function rateLimit(name, maxRequests, windowMs) {
  return (req, res, next) => {
    const key = `${name}:${clientIp(req)}`;
    const now = Date.now();
    const existing = rateLimitBuckets.get(key);
    const bucket = existing && existing.resetAt > now
      ? existing
      : { count: 0, resetAt: now + windowMs };

    bucket.count += 1;
    rateLimitBuckets.set(key, bucket);

    if (bucket.count > maxRequests) {
      res.setHeader("Retry-After", Math.ceil((bucket.resetAt - now) / 1000));
      return res.status(429).send("Too many requests. Try again later.");
    }

    next();
  };
}

const authRateLimit = rateLimit("auth", 12, 15 * 60 * 1000);
const commentRateLimit = rateLimit("comment", 30, 10 * 60 * 1000);
const downloadRateLimit = rateLimit("download", 90, 10 * 60 * 1000);
const uploadRateLimit = rateLimit("upload", 20, 10 * 60 * 1000);
const adminRateLimit = rateLimit("admin", 60, 10 * 60 * 1000);

const rateLimitCleanup = setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateLimitBuckets) {
    if (bucket.resetAt <= now) {
      rateLimitBuckets.delete(key);
    }
  }
}, 10 * 60 * 1000);
rateLimitCleanup.unref();

function getSupabaseEnv() {
  const url = (process.env.SUPABASE_URL || "").trim();
  const anonKey = (process.env.SUPABASE_ANON_KEY || "").trim();
  const bucket = (process.env.SUPABASE_STORAGE_BUCKET || "mods").trim();

  return {
    url,
    anonKey,
    bucket,
    hasValidUrl: /^https?:\/\/.+/.test(url),
  };
}

fs.mkdirSync(uploadsDir, { recursive: true });

function slugify(value) {
  return String(value)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

function stringInput(value, maxLength = 500) {
  if (Array.isArray(value)) {
    return "";
  }
  return String(value || "").trim().slice(0, maxLength);
}

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function hashEmailCode(id, purpose, code) {
  return crypto.createHmac("sha256", sessionSecret).update(`${id}:${purpose}:${code}`).digest("hex");
}

function maskEmail(email) {
  const [local, domain] = String(email || "").split("@");
  if (!local || !domain) return "your email address";
  return `${local.slice(0, 1)}***@${domain}`;
}

async function issueEmailChallenge({ email, purpose, payload }) {
  const id = makeId("email");
  const code = String(crypto.randomInt(100000, 1000000));
  const expiryMinutes = Math.min(30, Math.max(5, Number(process.env.AUTH_CODE_EXPIRY_MINUTES || 10)));
  const challenge = {
    id,
    email,
    purpose,
    codeHash: hashEmailCode(id, purpose, code),
    payload,
    attempts: 0,
    expiresAt: new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString(),
    createdAt: new Date().toISOString(),
  };

  await saveEmailChallenge(challenge);
  try {
    await sendEmailCode({ to: email, code, purpose });
  } catch (error) {
    await deleteEmailChallenge(id);
    throw error;
  }
  return challenge;
}

function signPayload(payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = crypto
    .createHmac("sha256", sessionSecret)
    .update(body)
    .digest("base64url");
  return `${body}.${signature}`;
}

function verifyPayload(token) {
  try {
    const [body, signature] = String(token || "").split(".");
    if (!body || !signature) {
      return null;
    }

    const expected = crypto
      .createHmac("sha256", sessionSecret)
      .update(body)
      .digest("base64url");

    if (
      signature.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    ) {
      return null;
    }

    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch (_error) {
    return null;
  }
}

async function getGameBySlug(slug) {
  return (await listGames()).find((game) => game.slug === slug);
}

async function normalizeMod(mod) {
  const game = await getGameBySlug(mod.gameSlug);
  const galleryImages = Array.isArray(mod.galleryImages) ? mod.galleryImages : [];
  const changelog = Array.isArray(mod.changelog) && mod.changelog.length
    ? mod.changelog
    : mod.version
      ? [{
          id: `${mod.id || mod.slug}_initial`,
          version: mod.version,
          notes: "Initial release.",
          createdAt: mod.createdAt,
        }]
      : [];
  return {
    ...mod,
    game: game ? game.name : mod.game,
    isSafe: mod.verificationStatus === "safe",
    iconUrl: await getModPreviewUrl(mod.iconFilePath),
    galleryImages: await Promise.all(galleryImages.map(async (image) => ({
      ...image,
      url: await getModPreviewUrl(image.filePath),
    }))),
    installInstructions: mod.installInstructions || "",
    changelog,
    comments: Array.isArray(mod.comments)
      ? [...mod.comments].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
      : [],
  };
}

function hasGoogleAuth() {
  return Boolean((process.env.GOOGLE_CLIENT_ID || "").trim() && (process.env.GOOGLE_CLIENT_SECRET || "").trim());
}

function getRecaptchaConfig() {
  return {
    siteKey: (process.env.RECAPTCHA_SITE_KEY || "").trim(),
    secretKey: (process.env.RECAPTCHA_SECRET_KEY || "").trim(),
  };
}

function isRecaptchaEnabled() {
  const { siteKey, secretKey } = getRecaptchaConfig();
  return Boolean(siteKey && secretKey);
}

async function verifyRecaptcha(req) {
  if (!isRecaptchaEnabled()) {
    return true;
  }

  const token = String(req.body["g-recaptcha-response"] || "").trim();
  if (!token) {
    return false;
  }

  try {
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        secret: getRecaptchaConfig().secretKey,
        response: token,
        remoteip: req.ip,
      }),
    });

    if (!response.ok) {
      return false;
    }

    const result = await response.json();
    if (!result.success) {
      return false;
    }

    return true;
  } catch (error) {
    console.error("reCAPTCHA verification failed:", error.message);
    return false;
  }
}

function getBaseUrl(req) {
  const configuredUrl = (process.env.PUBLIC_SITE_URL || "").trim().replace(/\/+$/, "");
  if (configuredUrl) {
    return configuredUrl;
  }

  const protocol = req.headers["x-forwarded-proto"] || req.protocol || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${port}`;
  return `${protocol}://${host}`;
}

function getGoogleRedirectUri(req) {
  return (process.env.GOOGLE_REDIRECT_URI || "").trim() || `${getBaseUrl(req)}/auth/google/callback`;
}

function createGoogleAuthUrl(req) {
  const clientId = (process.env.GOOGLE_CLIENT_ID || "").trim();
  const redirectUri = getGoogleRedirectUri(req);
  const state = crypto.randomBytes(16).toString("hex");
  req.session.googleState = state;

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "select_account");
  return url.toString();
}

async function exchangeGoogleCode(code, req) {
  const redirectUri = getGoogleRedirectUri(req);
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      code,
      client_id: (process.env.GOOGLE_CLIENT_ID || "").trim(),
      client_secret: (process.env.GOOGLE_CLIENT_SECRET || "").trim(),
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenRes.ok) {
    throw new Error("Google token exchange failed.");
  }

  const tokenData = await tokenRes.json();
  const userRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: {
      authorization: `Bearer ${tokenData.access_token}`,
    },
  });

  if (!userRes.ok) {
    throw new Error("Google user lookup failed.");
  }

  return userRes.json();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 1024 * 1024 * 250,
    files: 7,
    fields: 20,
    parts: 30,
  },
});

const imageExtensions = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif"]);

function isImageFileName(fileName) {
  return imageExtensions.has(path.extname(String(fileName || "")).toLowerCase());
}

function isImageFile(file) {
  return Boolean(file && file.originalname && isImageFileName(file.originalname) && String(file.mimetype || "").startsWith("image/"));
}

function makeChangelogEntry(version, notes) {
  const cleanNotes = String(notes || "").trim() || "Initial release.";
  return {
    id: makeId("release"),
    version: String(version || "").trim(),
    notes: cleanNotes,
    createdAt: new Date().toISOString(),
  };
}

async function deleteModStorage(mod) {
  const paths = [
    mod.filePath || mod.fileName,
    mod.iconFilePath,
    ...(Array.isArray(mod.galleryImages) ? mod.galleryImages.map((image) => image.filePath) : []),
  ].filter(Boolean);

  await Promise.all(paths.map((filePath) => deleteModFile(filePath)));
}

function appendSetCookie(res, cookie) {
  const existing = res.getHeader("Set-Cookie");
  if (!existing) {
    res.setHeader("Set-Cookie", cookie);
  } else if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", [...existing, cookie]);
  } else {
    res.setHeader("Set-Cookie", [existing, cookie]);
  }
}

function serializeSessionCookie(value, options = {}) {
  const parts = [
    `modify_at_session=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=604800",
  ];

  if (process.env.VERCEL) {
    parts.push("Secure");
  }

  if (options.expires) {
    parts.push(`Expires=${options.expires.toUTCString()}`);
    parts.push("Max-Age=0");
  }

  return parts.join("; ");
}

function parseCookies(cookieHeader) {
  return String(cookieHeader || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, part) => {
      const separator = part.indexOf("=");
      if (separator === -1) {
        return cookies;
      }
      cookies[part.slice(0, separator)] = decodeURIComponent(part.slice(separator + 1));
      return cookies;
    }, {});
}

function cookieSession(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const restored = verifyPayload(cookies.modify_at_session) || {};
  let destroyed = false;

  req.session = { ...restored };
  req.session.destroy = (callback) => {
    destroyed = true;
    appendSetCookie(res, serializeSessionCookie("", { expires: new Date(0) }));
    callback();
  };

  const writeHead = res.writeHead.bind(res);
  res.writeHead = (...args) => {
    if (!destroyed) {
      const sessionData = Object.fromEntries(
        Object.entries(req.session).filter(([, value]) => typeof value !== "function")
      );
      appendSetCookie(res, serializeSessionCookie(signPayload(sessionData)));
    }
    return writeHead(...args);
  };

  next();
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use((req, res, next) => {
  const scriptSources = [
    "'self'",
    "'unsafe-inline'",
    "https://www.google.com/recaptcha/",
    "https://www.gstatic.com/recaptcha/",
    "https://www.recaptcha.net/recaptcha/",
    "https://cdn.jsdelivr.net",
  ].join(" ");

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Origin-Agent-Cluster", "?1");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      `script-src ${scriptSources}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://*.supabase.co https://www.google.com https://www.gstatic.com https://www.recaptcha.net",
      "frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/ https://www.recaptcha.net/recaptcha/",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; ")
  );

  if (req.secure || req.headers["x-forwarded-proto"] === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  }

  next();
});

app.use("/styles", express.static(path.join(__dirname, "..", "public", "styles"), { dotfiles: "deny" }));
app.use("/uploads", express.static(uploadsDir, {
  dotfiles: "deny",
  setHeaders(res, filePath) {
    res.setHeader("Cache-Control", "private, no-store");
    if (/\.(php|phtml|phar|cgi|pl|py|asp|aspx|jsp|sh|bash|exe|dll|js|html|htm|svg)$/i.test(filePath)) {
      res.setHeader("Content-Disposition", "attachment");
      res.setHeader("Content-Type", "application/octet-stream");
    }
  },
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb", parameterLimit: 50 }));
app.use(process.env.VERCEL
  ? cookieSession
  : session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7,
      },
    }));

app.use((req, _res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  next();
});

function isSameOriginRequest(req) {
  const requestHost = String(req.headers["x-forwarded-host"] || req.headers.host || "").toLowerCase();
  const origin = req.headers.origin || req.headers.referer;
  if (!origin) {
    return true;
  }

  try {
    return new URL(origin).host.toLowerCase() === requestHost;
  } catch (_error) {
    return false;
  }
}

app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || isSameOriginRequest(req)) {
    return next();
  }

  res.status(403).send("Cross-origin request blocked.");
});

app.use(async (req, res, next) => {
  await storeReady;
  const users = await listUsers();
  const currentUser = users.find((user) => user.id === req.session.userId) || null;
  res.locals.currentUser = currentUser;
  res.locals.csrfToken = req.session.csrfToken;
  res.locals.assetVersion = process.env.VERCEL_GIT_COMMIT_SHA || "dev";
  res.setHeader("Cache-Control", "no-store");
  res.locals.notice = req.session.notice || null;
  res.locals.googleAuthEnabled = hasGoogleAuth();
  res.locals.recaptchaSiteKey = getRecaptchaConfig().siteKey;
  res.locals.recaptchaEnabled = isRecaptchaEnabled();
  const supabaseEnv = getSupabaseEnv();
  res.locals.supabaseBrowserConfig =
    isSupabaseEnabled() && supabaseEnv.anonKey
      ? {
          url: supabaseEnv.url,
          anonKey: supabaseEnv.anonKey,
          bucket: supabaseEnv.bucket,
        }
      : null;
  res.locals.hostedWithoutSupabase = isHostedWithoutSupabase();
  delete req.session.notice;
  next();
});

app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const expected = String(req.session.csrfToken || "");
  const supplied = String(req.headers["x-csrf-token"] || (req.body && req.body._csrf) || "");
  if (!expected || supplied.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return res.status(403).send("Request could not be verified.");
  }
  next();
});

function requireAuth(req, res, next) {
  if (!res.locals.currentUser) {
    if (req.accepts(["html", "json"]) === "json") {
      return res.status(401).json({ error: "Sign in again, then try uploading." });
    }
    req.session.notice = "Sign in to access that page.";
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!res.locals.currentUser || res.locals.currentUser.role !== "admin") {
    req.session.notice = "Admin access only.";
    return res.redirect("/login");
  }
  next();
}

async function logActivity(user, action, targetType, targetId, details) {
  const entries = await listActivity();
  entries.push({
    id: makeId("activity"),
    actorId: user.id,
    actorName: user.username,
    action,
    targetType,
    targetId: targetId || null,
    details: details || "",
    createdAt: new Date().toISOString(),
  });
  await saveActivity(entries.slice(-100));
}

async function renderPage(res, view, locals = {}, next) {
  const games = await listGames();
  const mods = await Promise.all((await listMods()).map(normalizeMod));
  res.render(
    view,
    {
      allGames: games,
      allMods: mods,
      ...locals,
    },
    (err, html) => {
      if (err) {
        if (next) {
          return next(err);
        }
        throw err;
      }
      res.send(html);
    }
  );
}

app.get("/", async (_req, res, next) => {
  const mods = (await Promise.all((await listMods()).map(normalizeMod))).sort((a, b) => b.downloadCount - a.downloadCount);
  const newestMods = [...mods].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 6);
  const featuredMods = mods.slice(0, 3);
  const games = await listGames();
  const gameDirectory = games
    .map((game) => {
      const gameMods = mods.filter((mod) => mod.gameSlug === game.slug);
      const latestMod = [...gameMods].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
      return {
        ...game,
        modCount: gameMods.length,
        safeCount: gameMods.filter((mod) => mod.isSafe).length,
        coverUrl: latestMod ? latestMod.iconUrl : null,
        latestTitle: latestMod ? latestMod.title : null,
      };
    })
    .sort((a, b) => b.modCount - a.modCount || a.name.localeCompare(b.name));
  await renderPage(res, "home", {
    featuredMods,
    newestMods,
    gameDirectory,
    totalMods: mods.length,
    totalCreators: new Set(mods.map((mod) => mod.authorId)).size,
  }, next);
});

app.get("/help", async (_req, res, next) => {
  await renderPage(res, "help", {}, next);
});

app.get("/terms", async (_req, res, next) => {
  await renderPage(res, "terms", {}, next);
});

app.get("/privacy", async (_req, res, next) => {
  await renderPage(res, "privacy", {}, next);
});

app.get("/ads.txt", (_req, res) => {
  res.type("text/plain").send("google.com, pub-7721626603982200, DIRECT, f08c47fec0942fa0\n");
});

app.get("/robots.txt", (_req, res) => {
  res.type("text/plain").send([
    "User-agent: *",
    "Allow: /",
    "",
    "User-agent: Mediapartners-Google",
    "Allow: /",
    "",
    "User-agent: Google-Display-Ads-Bot",
    "Allow: /",
    "",
  ].join("\n"));
});

app.get("/mods", async (req, res, next) => {
  const query = stringInput(req.query.q, 100).toLowerCase();
  const game = stringInput(req.query.game, 80);
  const category = stringInput(req.query.category, 80);
  const status = stringInput(req.query.status, 20);
  const sort = stringInput(req.query.sort, 20) || "newest";
  let mods = (await Promise.all((await listMods()).map(normalizeMod))).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  if (query) {
    mods = mods.filter((mod) =>
      [mod.title, mod.summary, mod.game, mod.category, mod.authorName]
        .join(" ")
        .toLowerCase()
        .includes(query)
    );
  }

  if (game) {
    mods = mods.filter((mod) => mod.gameSlug === game);
  }

  if (category) {
    mods = mods.filter((mod) => mod.category.toLowerCase() === category.toLowerCase());
  }

  if (status === "safe") {
    mods = mods.filter((mod) => mod.isSafe);
  }

  if (sort === "popular") {
    mods.sort((a, b) => b.downloadCount - a.downloadCount);
  } else if (sort === "oldest") {
    mods.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  }

  await renderPage(res, "mods", {
    mods,
    query,
    game,
    category,
    status,
    sort,
  }, next);
});

app.get("/creators/:username", async (req, res, next) => {
  const users = await listUsers();
  const username = stringInput(req.params.username, 32);
  const creator = users.find((user) => user.username.toLowerCase() === username.toLowerCase());
  if (!creator) {
    return res.status(404).render("not-found", { message: "That creator does not exist." });
  }

  const creatorMods = (await Promise.all((await listMods())
    .filter((mod) => mod.authorId === creator.id)
    .map(normalizeMod)))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  await renderPage(res, "creator", { creator, creatorMods }, next);
});

app.get("/mods/:slug", async (req, res, next) => {
  const slug = stringInput(req.params.slug, 80);
  const rawMod = (await listMods()).find((entry) => entry.slug === slug);
  if (!rawMod) {
    return res.status(404).render("not-found", { message: "That mod does not exist yet." });
  }

  const mod = await normalizeMod(rawMod);
  const relatedMods = await Promise.all((await listMods())
    .filter((entry) => entry.id !== rawMod.id && entry.gameSlug === rawMod.gameSlug)
    .slice(0, 3)
    .map(normalizeMod));

  await renderPage(res, "mod-detail", { mod, relatedMods }, next);
});

async function handleModDownload(req, res, next) {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.slug === req.params.slug);
  if (!mod) {
    return res.status(404).render("not-found", { message: "That mod does not exist yet." });
  }

  const filePath = mod.filePath || mod.fileName;

  try {
    const downloadUrl = await getModDownloadUrl(filePath, mod.originalFileName || mod.fileName);
    mod.downloadCount += 1;
    await saveMods(mods);

    // Proxy the private object so browsers receive an attachment response from
    // modify.at instead of navigating to the signed storage URL.
    if (isSupabaseEnabled()) {
      const fileResponse = await fetch(downloadUrl);
      if (!fileResponse.ok || !fileResponse.body) {
        throw new Error(`Storage download failed with status ${fileResponse.status}`);
      }

      const downloadName = path.basename(mod.originalFileName || mod.fileName || "mod-download")
        .replace(/[\r\n"\\]/g, "_");
      res.setHeader("Content-Disposition", `attachment; filename="${downloadName}"`);
      res.setHeader("Content-Type", fileResponse.headers.get("content-type") || "application/octet-stream");
      const contentLength = fileResponse.headers.get("content-length");
      if (contentLength) {
        res.setHeader("Content-Length", contentLength);
      }
      return Readable.fromWeb(fileResponse.body).pipe(res);
    }

    return res.redirect(downloadUrl);
  } catch (error) {
    console.error("Download link failed", {
      modSlug: mod.slug,
      filePath,
      message: error.message,
      status: error.status,
    });
    req.session.notice = "Could not prepare download. Try uploading this mod again.";
    return res.redirect(`/mods/${mod.slug}`);
  }
}

app.get("/mods/:slug/download", downloadRateLimit, handleModDownload);
app.post("/mods/:slug/download", downloadRateLimit, handleModDownload);

app.post("/mods/:slug/comments", requireAuth, commentRateLimit, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.slug === req.params.slug);
  const content = stringInput(req.body.content, 1000);

  if (!mod) {
    return res.status(404).render("not-found", { message: "That mod does not exist yet." });
  }

  if (!content) {
    req.session.notice = "Write a comment before posting.";
    return res.redirect(`/mods/${mod.slug}`);
  }

  if (content.length > 1000) {
    req.session.notice = "Keep comments under 1000 characters.";
    return res.redirect(`/mods/${mod.slug}`);
  }

  if (!Array.isArray(mod.comments)) {
    mod.comments = [];
  }

  mod.comments.push({
    id: makeId("comment"),
    authorId: res.locals.currentUser.id,
    authorName: res.locals.currentUser.username,
    content,
    createdAt: new Date().toISOString(),
  });

  await saveMods(mods);
  req.session.notice = "Comment posted.";
  res.redirect(`/mods/${mod.slug}`);
});

app.post("/mods/:slug/report", requireAuth, commentRateLimit, async (req, res) => {
  const mod = (await listMods()).find((entry) => entry.slug === req.params.slug);
  const reason = stringInput(req.body.reason, 30);
  const details = stringInput(req.body.details, 1000);
  const allowedReasons = new Set(["malware", "broken", "copyright", "misleading", "other"]);

  if (!mod || !allowedReasons.has(reason)) {
    req.session.notice = "Choose a valid report reason.";
    return res.redirect(`/mods/${req.params.slug}`);
  }

  const reports = await listReports();
  reports.push({
    id: makeId("report"),
    modId: mod.id,
    modSlug: mod.slug,
    modTitle: mod.title,
    reporterId: res.locals.currentUser.id,
    reporterName: res.locals.currentUser.username,
    reason,
    details: details.slice(0, 1000),
    status: "open",
    createdAt: new Date().toISOString(),
  });
  await saveReports(reports);
  req.session.notice = "Thanks. Your report was sent to the moderation team.";
  res.redirect(`/mods/${mod.slug}`);
});

app.get("/register", async (_req, res, next) => {
  await renderPage(res, "register", {}, next);
});

app.post("/register", authRateLimit, async (req, res) => {
  const normalizedEmail = stringInput(req.body.email, 254).toLowerCase();
  const cleanUsername = stringInput(req.body.username, 32);
  const password = stringInput(req.body.password, 200);
  const users = await listUsers();

  if (!(await verifyRecaptcha(req, "register"))) {
    req.session.notice = "Please finish the reCAPTCHA check before creating an account.";
    return res.redirect("/register");
  }

  if (!cleanUsername || !normalizedEmail || !password) {
    req.session.notice = "Fill out every field to create an account.";
    return res.redirect("/register");
  }

  if (cleanUsername.length > 32 || normalizedEmail.length > 254 || password.length < 8 || password.length > 200) {
    req.session.notice = "Use a shorter username or password, and check your email address.";
    return res.redirect("/register");
  }

  if (users.some((user) => user.email === normalizedEmail)) {
    req.session.notice = "That email is already in use.";
    return res.redirect("/register");
  }

  if (users.some((user) => user.username.toLowerCase() === cleanUsername.toLowerCase())) {
    req.session.notice = "That username is already taken.";
    return res.redirect("/register");
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: makeId("user"),
    username: cleanUsername,
    email: normalizedEmail,
    passwordHash,
    authProvider: "local",
    role: "user",
    createdAt: new Date().toISOString(),
  };

  try {
    const challenge = await issueEmailChallenge({
      email: user.email,
      purpose: "signup",
      payload: user,
    });
    req.session.emailChallengeId = challenge.id;
    req.session.emailChallengePurpose = "signup";
    req.session.notice = "Check your email for a six-digit code.";
  } catch (error) {
    console.error("Failed to send signup code:", error.message);
    req.session.notice = "We could not send the verification email. Check SMTP settings and try again.";
    return res.redirect("/register");
  }
  res.redirect("/verify-email");
});

app.get("/login", async (_req, res, next) => {
  await renderPage(res, "login", {}, next);
});

app.post("/login", authRateLimit, async (req, res) => {
  const normalizedEmail = stringInput(req.body.email, 254).toLowerCase();
  const password = stringInput(req.body.password, 200);
  const user = (await listUsers()).find((entry) => entry.email === normalizedEmail);

  if (!(await verifyRecaptcha(req, "login"))) {
    req.session.notice = "Please finish the reCAPTCHA check before signing in.";
    return res.redirect("/login");
  }

  if (!user || !user.passwordHash || !(await bcrypt.compare(password || "", user.passwordHash))) {
    req.session.notice = "We could not match that email and password.";
    return res.redirect("/login");
  }

  try {
    const challenge = await issueEmailChallenge({
      email: user.email,
      purpose: "login",
      payload: { userId: user.id },
    });
    req.session.emailChallengeId = challenge.id;
    req.session.emailChallengePurpose = "login";
    req.session.notice = "Check your email for a six-digit sign-in code.";
    res.redirect("/verify-email");
  } catch (error) {
    console.error("Failed to send login code:", error.message);
    req.session.notice = "We could not send the sign-in code. Check SMTP settings and try again.";
    res.redirect("/login");
  }
});

app.get("/verify-email", async (req, res, next) => {
  const challenge = await getEmailChallenge(req.session.emailChallengeId);
  await renderPage(res, "verify-email", {
    pendingEmail: challenge ? maskEmail(challenge.email) : "your email address",
  }, next);
});

app.post("/verify-email", authRateLimit, async (req, res) => {
  const challengeId = req.session.emailChallengeId;
  const purpose = req.session.emailChallengePurpose;
  const challenge = await getEmailChallenge(challengeId);
  const code = stringInput(req.body.code, 6);

  if (!challenge || challenge.purpose !== purpose || new Date(challenge.expiresAt).getTime() <= Date.now()) {
    delete req.session.emailChallengeId;
    delete req.session.emailChallengePurpose;
    req.session.notice = "That code expired. Start again.";
    return res.redirect(purpose === "signup" ? "/register" : "/login");
  }

  if (challenge.attempts >= 5) {
    await deleteEmailChallenge(challenge.id);
    delete req.session.emailChallengeId;
    delete req.session.emailChallengePurpose;
    req.session.notice = "Too many incorrect codes. Start again.";
    return res.redirect(purpose === "signup" ? "/register" : "/login");
  }

  const expectedHash = hashEmailCode(challenge.id, challenge.purpose, code);
  if (code.length !== 6 || !crypto.timingSafeEqual(Buffer.from(expectedHash), Buffer.from(challenge.codeHash))) {
    challenge.attempts += 1;
    await saveEmailChallenge(challenge);
    req.session.notice = "That code is incorrect.";
    return res.redirect("/verify-email");
  }

  await deleteEmailChallenge(challenge.id);
  delete req.session.emailChallengeId;
  delete req.session.emailChallengePurpose;

  if (purpose === "signup") {
    const users = await listUsers();
    const pendingUser = challenge.payload;
    if (users.some((entry) => entry.email === pendingUser.email || entry.username.toLowerCase() === pendingUser.username.toLowerCase())) {
      req.session.notice = "That account information is already in use.";
      return res.redirect("/register");
    }
    users.push(pendingUser);
    await saveUsers(users);
    req.session.userId = pendingUser.id;
    try {
      await sendWelcomeEmail(pendingUser);
    } catch (error) {
      console.error("Failed to send welcome email:", error.message);
    }
    req.session.notice = "Your modify.at account is live. Welcome!";
    return res.redirect("/dashboard");
  }

  const user = (await listUsers()).find((entry) => entry.id === challenge.payload.userId);
  if (!user) {
    req.session.notice = "That account no longer exists.";
    return res.redirect("/login");
  }
  req.session.userId = user.id;
  req.session.notice = `Welcome back, ${user.username}.`;
  res.redirect("/dashboard");
});

app.post("/verify-email/resend", authRateLimit, async (req, res) => {
  const challengeId = req.session.emailChallengeId;
  const purpose = req.session.emailChallengePurpose;
  const previous = await getEmailChallenge(challengeId);
  if (!previous || !["signup", "login"].includes(purpose)) {
    req.session.notice = "Start the sign-in or signup process again.";
    return res.redirect("/login");
  }

  try {
    await deleteEmailChallenge(previous.id);
    const challenge = await issueEmailChallenge({ email: previous.email, purpose, payload: previous.payload });
    req.session.emailChallengeId = challenge.id;
    req.session.notice = "A new code was sent to your email.";
  } catch (error) {
    console.error("Failed to resend email code:", error.message);
    req.session.notice = "We could not resend the code. Try again later.";
  }
  res.redirect("/verify-email");
});

app.get("/auth/google", (req, res) => {
  if (!hasGoogleAuth()) {
    req.session.notice = "Google sign-in needs GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Vercel.";
    return res.redirect("/login");
  }

  res.redirect(createGoogleAuthUrl(req));
});

app.get("/auth/google/callback", async (req, res) => {
  const expectedState = req.session.googleState;
  delete req.session.googleState;
  if (!req.query.code || !req.query.state || req.query.state !== expectedState) {
    req.session.notice = "Google sign-in could not be verified.";
    return res.redirect("/login");
  }

  try {
    const googleUser = await exchangeGoogleCode(req.query.code, req);
    if (!googleUser.email || googleUser.email_verified !== true) {
      throw new Error("Google account email is not verified.");
    }
    const users = await listUsers();
    let user = users.find((entry) => entry.email === String(googleUser.email || "").toLowerCase());

    if (!user) {
      const preferredUsername = slugify(googleUser.name || googleUser.email.split("@")[0]).slice(0, 24) || `user${Date.now()}`;
      let username = preferredUsername;
      let suffix = 2;
      while (users.some((entry) => entry.username.toLowerCase() === username.toLowerCase())) {
        username = `${preferredUsername}${suffix}`;
        suffix += 1;
      }

      user = {
        id: makeId("user"),
        username,
        email: String(googleUser.email || "").toLowerCase(),
        authProvider: "google",
        googleId: googleUser.sub,
        role: "user",
        createdAt: new Date().toISOString(),
      };
      users.push(user);
      await saveUsers(users);
    } else if (!user.googleId) {
      user.googleId = googleUser.sub;
      user.authProvider = user.authProvider || "google";
      await saveUsers(users);
    }

    req.session.userId = user.id;
    req.session.notice = `Signed in with Google as ${user.username}.`;
    res.redirect("/dashboard");
  } catch (error) {
    console.error("Google sign-in failed:", error.message);
    req.session.notice = "Google sign-in failed. Check your Google app settings.";
    res.redirect("/login");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/dashboard", requireAuth, async (req, res, next) => {
  const userMods = (await Promise.all((await listMods())
    .filter((mod) => mod.authorId === res.locals.currentUser.id)
    .map(normalizeMod)))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  await renderPage(res, "dashboard", {
    userMods,
  }, next);
});

app.get("/upload", requireAuth, async (_req, res, next) => {
  await renderPage(res, "upload", {}, next);
});

app.get("/debug/config", (req, res) => {
  if (!res.locals.currentUser || res.locals.currentUser.role !== "admin") {
    return res.status(404).render("not-found", { message: "That page could not be found." });
  }

  const supabaseEnv = getSupabaseEnv();
  res.json({
    vercel: Boolean(process.env.VERCEL),
    supabaseUrl: Boolean(supabaseEnv.url),
    supabaseUrlValid: supabaseEnv.hasValidUrl,
    supabaseAnonKey: Boolean(supabaseEnv.anonKey),
    supabaseServiceRoleKey: Boolean((process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim()),
    supabaseStorageBucket: supabaseEnv.bucket,
    supabaseServerEnabled: isSupabaseEnabled(),
    supabaseBrowserEnabled: Boolean(res.locals.supabaseBrowserConfig),
    googleAuthEnabled: hasGoogleAuth(),
    recaptchaSiteKey: Boolean(getRecaptchaConfig().siteKey),
    recaptchaSecretKey: Boolean(getRecaptchaConfig().secretKey),
    recaptchaEnabled: isRecaptchaEnabled(),
    googleRedirectUri: getGoogleRedirectUri(req),
    hostedWithoutSupabase: isHostedWithoutSupabase(),
    commit: process.env.VERCEL_GIT_COMMIT_SHA || null,
  });
});

app.post("/upload/sign", requireAuth, uploadRateLimit, async (req, res) => {
  if (!isSupabaseEnabled() || !getSupabaseEnv().anonKey) {
    return res.status(400).json({ error: "Supabase uploads are not configured." });
  }

  const originalFileName = stringInput(req.body.originalFileName, 255);
  const fileSize = Number(req.body.fileSize || 0);
  const iconOriginalFileName = stringInput(req.body.iconOriginalFileName, 255);
  const galleryOriginalFileNames = Array.isArray(req.body.galleryOriginalFileNames)
    ? req.body.galleryOriginalFileNames.map((name) => String(name || "").trim()).filter(Boolean).slice(0, 6)
    : [];

  if (!originalFileName) {
    return res.status(400).json({ error: "Choose a mod file first." });
  }

  if (!Number.isSafeInteger(fileSize) || fileSize <= 0 || fileSize > 250 * 1024 * 1024) {
    return res.status(400).json({ error: "That file looks empty. Download it to the device first, then choose it again." });
  }

  if (iconOriginalFileName && !isImageFileName(iconOriginalFileName)) {
    return res.status(400).json({ error: "The mod icon must be an image file." });
  }

  if (galleryOriginalFileNames.some((name) => !isImageFileName(name))) {
    return res.status(400).json({ error: "Gallery pictures must be image files." });
  }

  if (galleryOriginalFileNames.some((name) => name.length > 255)) {
    return res.status(400).json({ error: "Gallery filenames are too long." });
  }

  const uploadId = makeId("upload");
  const signedUpload = await createSignedModUpload(originalFileName, uploadId);
  const signedIconUpload = iconOriginalFileName
    ? await createSignedAssetUpload(iconOriginalFileName, uploadId, "icon")
    : null;
  const signedGalleryUploads = await Promise.all(
    galleryOriginalFileNames.map((name) => createSignedAssetUpload(name, uploadId, "gallery"))
  );
  const uploadToken = signPayload({
    uploadId,
    fileName: signedUpload.fileName,
    filePath: signedUpload.filePath,
    originalFileName,
    fileSize,
    icon: signedIconUpload
      ? {
          fileName: signedIconUpload.fileName,
          filePath: signedIconUpload.filePath,
          originalFileName: iconOriginalFileName,
        }
      : null,
    gallery: signedGalleryUploads.map((galleryUpload, index) => ({
      fileName: galleryUpload.fileName,
      filePath: galleryUpload.filePath,
      originalFileName: galleryOriginalFileNames[index],
    })),
    createdAt: Date.now(),
  });

  res.json({
    ...signedUpload,
    icon: signedIconUpload,
    gallery: signedGalleryUploads,
    uploadToken,
  });
});

app.post("/upload/complete", requireAuth, uploadRateLimit, async (req, res) => {
  const title = stringInput(req.body.title, 120);
  const gameSlug = stringInput(req.body.gameSlug, 80);
  const category = stringInput(req.body.category, 80);
  const version = stringInput(req.body.version, 40);
  const summary = stringInput(req.body.summary, 140);
  const description = stringInput(req.body.description, 10000);
  const installInstructions = stringInput(req.body.installInstructions, 10000);
  const releaseNotes = stringInput(req.body.releaseNotes, 5000);
  const uploadToken = stringInput(req.body.uploadToken, 5000);
  const uploadedFile = verifyPayload(uploadToken);
  const game = await getGameBySlug(gameSlug);

  if (!uploadedFile || Date.now() - uploadedFile.createdAt > 1000 * 60 * 60) {
    req.session.notice = "Upload expired. Try again.";
    return res.redirect("/upload");
  }

  if (!title || !gameSlug || !category || !version || !summary || !description) {
    req.session.notice = "Every field and a file upload are required.";
    return res.redirect("/upload");
  }

  if (!game) {
    req.session.notice = "Choose a valid game.";
    return res.redirect("/upload");
  }

  if (!game.categories.includes(category)) {
    req.session.notice = "Choose a valid category for that game.";
    return res.redirect("/upload");
  }

  const mods = await listMods();
  const slugRoot = slugify(title) || makeId("mod");
  const existingSlugs = new Set(mods.map((mod) => mod.slug));
  let slug = slugRoot;
  let suffix = 2;

  while (existingSlugs.has(slug)) {
    slug = `${slugRoot}-${suffix}`;
    suffix += 1;
  }

  mods.push({
    id: makeId("mod"),
    slug,
    title: title.trim(),
    gameSlug: game.slug,
    category: category.trim(),
    version: version.trim(),
    summary: summary.trim(),
    description: description.trim(),
    fileName: uploadedFile.fileName,
    filePath: uploadedFile.filePath,
    originalFileName: uploadedFile.originalFileName,
    fileSize: uploadedFile.fileSize,
    iconFileName: uploadedFile.icon ? uploadedFile.icon.fileName : null,
    iconFilePath: uploadedFile.icon ? uploadedFile.icon.filePath : null,
    galleryImages: Array.isArray(uploadedFile.gallery)
      ? uploadedFile.gallery.map((image) => ({
          id: makeId("image"),
          fileName: image.fileName,
          filePath: image.filePath,
          originalFileName: image.originalFileName,
          createdAt: new Date().toISOString(),
        }))
      : [],
    installInstructions: String(installInstructions || "").trim(),
    changelog: [makeChangelogEntry(version, releaseNotes)],
    downloadCount: 0,
    verificationStatus: "unverified",
    authorId: res.locals.currentUser.id,
    authorName: res.locals.currentUser.username,
    comments: [],
    createdAt: new Date().toISOString(),
  });

  await saveMods(mods);
  req.session.notice = "Your mod is now published as Unverified.";
  res.redirect(`/mods/${slug}`);
});

function rejectLegacyUploadOnVercel(_req, res, next) {
  if (process.env.VERCEL) {
    return res.status(410).json({ error: "Use the signed upload flow." });
  }
  next();
}

app.post("/upload", requireAuth, rejectLegacyUploadOnVercel, upload.fields([
  { name: "modFile", maxCount: 1 },
  { name: "iconFile", maxCount: 1 },
  { name: "galleryFiles", maxCount: 6 },
]), async (req, res) => {
  if (isHostedWithoutSupabase()) {
    req.session.notice = "Uploads need Supabase environment variables on Vercel.";
    return res.redirect("/upload");
  }

  const { title, gameSlug, category, version, summary, description, installInstructions, releaseNotes } = req.body;
  const game = await getGameBySlug(gameSlug);
  const modFile = req.files && req.files.modFile ? req.files.modFile[0] : null;
  const iconFile = req.files && req.files.iconFile ? req.files.iconFile[0] : null;
  const galleryFiles = req.files && req.files.galleryFiles ? req.files.galleryFiles : [];

  if (!title || !gameSlug || !category || !version || !summary || !description || !modFile) {
    req.session.notice = "Every field and a file upload are required.";
    return res.redirect("/upload");
  }

  if (iconFile && !isImageFile(iconFile)) {
    req.session.notice = "The mod icon must be an image file.";
    return res.redirect("/upload");
  }

  if (galleryFiles.some((file) => !isImageFile(file))) {
    req.session.notice = "Gallery pictures must be image files.";
    return res.redirect("/upload");
  }

  if (!game) {
    req.session.notice = "Choose a valid game.";
    return res.redirect("/upload");
  }

  if (!game.categories.includes(category)) {
    req.session.notice = "Choose a valid category for that game.";
    return res.redirect("/upload");
  }

  const mods = await listMods();
  const slugRoot = slugify(title) || makeId("mod");
  const existingSlugs = new Set(mods.map((mod) => mod.slug));
  let slug = slugRoot;
  let suffix = 2;

  while (existingSlugs.has(slug)) {
    slug = `${slugRoot}-${suffix}`;
    suffix += 1;
  }

  const uploadedFile = await uploadModFile(modFile, slug);
  const uploadedIcon = iconFile ? await uploadModFile(iconFile, `${slug}-icon`) : null;
  const uploadedGallery = await Promise.all(galleryFiles.map((file, index) => uploadModFile(file, `${slug}-gallery-${index + 1}`)));
  const mod = {
    id: makeId("mod"),
    slug,
    title: title.trim(),
    gameSlug: game.slug,
    category: category.trim(),
    version: version.trim(),
    summary: summary.trim(),
    description: description.trim(),
    fileName: uploadedFile.fileName,
    filePath: uploadedFile.filePath,
    originalFileName: modFile.originalname,
    fileSize: modFile.size,
    iconFileName: uploadedIcon ? uploadedIcon.fileName : null,
    iconFilePath: uploadedIcon ? uploadedIcon.filePath : null,
    galleryImages: uploadedGallery.map((image, index) => ({
      id: makeId("image"),
      fileName: image.fileName,
      filePath: image.filePath,
      originalFileName: galleryFiles[index].originalname,
      createdAt: new Date().toISOString(),
    })),
    installInstructions: String(installInstructions || "").trim(),
    changelog: [makeChangelogEntry(version, releaseNotes)],
    downloadCount: 0,
    verificationStatus: "unverified",
    authorId: res.locals.currentUser.id,
    authorName: res.locals.currentUser.username,
    comments: [],
    createdAt: new Date().toISOString(),
  };

  mods.push(mod);
  await saveMods(mods);
  req.session.notice = "Your mod is now published as Unverified.";
  res.redirect(`/mods/${mod.slug}`);
});

app.get("/admin", requireAdmin, async (req, res, next) => {
  const modQuery = String(req.query.modQuery || "").trim().toLowerCase();
  const modStatus = String(req.query.modStatus || "").trim();
  const users = (await listUsers()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  let mods = (await Promise.all((await listMods()).map(normalizeMod))).sort((a, b) => {
    if (a.isSafe !== b.isSafe) {
      return a.isSafe ? 1 : -1;
    }
    return new Date(b.createdAt) - new Date(a.createdAt);
  });
  const games = (await listGames()).sort((a, b) => a.name.localeCompare(b.name));
  const reports = (await listReports()).filter((report) => report.status === "open");
  const activity = await listActivity();

  if (modQuery) {
    mods = mods.filter((mod) =>
      [mod.title, mod.game, mod.category, mod.authorName, mod.summary]
        .join(" ")
        .toLowerCase()
        .includes(modQuery)
    );
  }

  if (modStatus === "safe") {
    mods = mods.filter((mod) => mod.isSafe);
  } else if (modStatus === "unverified") {
    mods = mods.filter((mod) => !mod.isSafe);
  }

  await renderPage(res, "admin", {
    users,
    mods,
    games,
    modQuery,
    modStatus,
    reports,
    activity,
  }, next);
});

app.post("/admin/reports/:id/:action", requireAdmin, adminRateLimit, async (req, res) => {
  const reports = await listReports();
  const report = reports.find((entry) => entry.id === req.params.id);
  if (!report || !["resolve", "dismiss"].includes(req.params.action)) {
    req.session.notice = "Report not found.";
    return res.redirect("/admin");
  }

  report.status = req.params.action === "resolve" ? "resolved" : "dismissed";
  report.resolvedAt = new Date().toISOString();
  report.resolvedBy = res.locals.currentUser.username;
  await saveReports(reports);
  await logActivity(res.locals.currentUser, `report_${report.status}`, "report", report.id, report.modTitle);
  req.session.notice = `Report ${report.status}.`;
  res.redirect("/admin");
});

app.post("/admin/games", requireAdmin, adminRateLimit, async (req, res) => {
  const name = stringInput(req.body.name, 100);
  if (!name) {
    req.session.notice = "Game name is required.";
    return res.redirect("/admin");
  }

  const games = await listGames();
  const slug = slugify(name);
  if (games.some((game) => game.slug === slug)) {
    req.session.notice = "That game already exists.";
    return res.redirect("/admin");
  }

  games.push({
    id: makeId("game"),
    name,
    slug,
    categories: [],
    createdAt: new Date().toISOString(),
  });
  await saveGames(games);
  req.session.notice = `${name} is now available for uploads.`;
  res.redirect("/admin");
});

app.post("/admin/games/:slug/categories", requireAdmin, adminRateLimit, async (req, res) => {
  const categoryName = stringInput(req.body.categoryName, 80);
  const games = await listGames();
  const game = games.find((entry) => entry.slug === req.params.slug);

  if (!game) {
    req.session.notice = "Game not found.";
    return res.redirect("/admin");
  }

  if (!categoryName) {
    req.session.notice = "Category name is required.";
    return res.redirect("/admin");
  }

  if (game.categories.some((entry) => entry.toLowerCase() === categoryName.toLowerCase())) {
    req.session.notice = "That category already exists for this game.";
    return res.redirect("/admin");
  }

  game.categories.push(categoryName);
  await saveGames(games);
  await logActivity(res.locals.currentUser, "category_added", "game", game.slug, `${categoryName} added`);
  req.session.notice = `${categoryName} added to ${game.name}.`;
  res.redirect("/admin");
});

app.post("/admin/mods/:id/verify", requireAdmin, adminRateLimit, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.id === req.params.id);
  if (!mod) {
    req.session.notice = "Mod not found.";
    return res.redirect("/admin");
  }

  mod.verificationStatus = "safe";
  await saveMods(mods);
  await logActivity(res.locals.currentUser, "mod_marked_safe", "mod", mod.id, mod.title);
  req.session.notice = `${mod.title} is now marked Safe.`;
  res.redirect("/admin");
});

app.post("/admin/mods/:id/unverify", requireAdmin, adminRateLimit, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.id === req.params.id);
  if (!mod) {
    req.session.notice = "Mod not found.";
    return res.redirect("/admin");
  }

  mod.verificationStatus = "unverified";
  await saveMods(mods);
  await logActivity(res.locals.currentUser, "mod_marked_unverified", "mod", mod.id, mod.title);
  req.session.notice = `${mod.title} is now marked Unverified.`;
  res.redirect("/admin");
});

app.post("/admin/mods/:id/delete", requireAdmin, adminRateLimit, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.id === req.params.id);
  if (!mod) {
    req.session.notice = "Mod not found.";
    return res.redirect("/admin");
  }

  await deleteModStorage(mod);
  await deleteModById(req.params.id);
  await logActivity(res.locals.currentUser, "mod_deleted", "mod", mod.id, mod.title);
  req.session.notice = `${mod.title} has been removed.`;
  res.redirect("/admin");
});

app.post("/admin/users/:id/delete", requireAdmin, adminRateLimit, async (req, res) => {
  if (req.params.id === res.locals.currentUser.id) {
    req.session.notice = "You cannot delete the admin account you are using.";
    return res.redirect("/admin");
  }

  const users = await listUsers();
  const user = users.find((entry) => entry.id === req.params.id);
  if (!user) {
    req.session.notice = "User not found.";
    return res.redirect("/admin");
  }

  const mods = await listMods();
  const userMods = mods.filter((mod) => mod.authorId === user.id);
  await Promise.all(userMods.map(deleteModStorage));
  await Promise.all(userMods.map((mod) => deleteModById(mod.id)));

  await deleteUserById(user.id);
  await logActivity(res.locals.currentUser, "user_deleted", "user", user.id, user.username);
  req.session.notice = `${user.username} and their mods have been removed.`;
  res.redirect("/admin");
});

app.use((err, req, res, _next) => {
  if (err instanceof multer.MulterError) {
    req.session.notice = "Upload failed. Check the file size and try again.";
    return res.redirect("/upload");
  }

  console.error(err);
  res.status(500).render("not-found", { message: "Something went sideways on the server." });
});

app.use((_req, res) => {
  res.status(404).render("not-found", { message: "That page could not be found." });
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`modify.at listening on http://localhost:${port}`);
  });
}

module.exports = app;
