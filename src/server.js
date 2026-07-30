const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const { loadEnv } = require("./env");
const { sendWelcomeEmail } = require("./mailer");

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
  uploadModFile,
  createSignedModUpload,
  deleteModFile,
  getModDownloadUrl,
} = require("./store");

const storeReady = initializeStore();

const app = express();
const port = process.env.PORT || 3000;
const uploadsDir = path.join(__dirname, "..", "uploads");

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

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function signPayload(payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = crypto
    .createHmac("sha256", process.env.SESSION_SECRET || "modify-at-dev-secret")
    .update(body)
    .digest("base64url");
  return `${body}.${signature}`;
}

function verifyPayload(token) {
  const [body, signature] = String(token || "").split(".");
  if (!body || !signature) {
    return null;
  }

  const expected = crypto
    .createHmac("sha256", process.env.SESSION_SECRET || "modify-at-dev-secret")
    .update(body)
    .digest("base64url");

  if (
    signature.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) {
    return null;
  }

  return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
}

async function getGameBySlug(slug) {
  return (await listGames()).find((game) => game.slug === slug);
}

async function normalizeMod(mod) {
  const game = await getGameBySlug(mod.gameSlug);
  return {
    ...mod,
    game: game ? game.name : mod.game,
    isSafe: mod.verificationStatus === "safe",
    comments: Array.isArray(mod.comments)
      ? [...mod.comments].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
      : [],
  };
}

function createGoogleAuthUrl(req) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${port}/auth/google/callback`;
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

async function exchangeGoogleCode(code) {
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${port}/auth/google/callback`;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
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
  limits: { fileSize: 1024 * 1024 * 250 },
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use("/styles", express.static(path.join(__dirname, "..", "public", "styles")));
app.use("/uploads", express.static(uploadsDir));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "modify-at-dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.use(async (req, res, next) => {
  await storeReady;
  const users = await listUsers();
  const currentUser = users.find((user) => user.id === req.session.userId) || null;
  res.locals.currentUser = currentUser;
  res.locals.notice = req.session.notice || null;
  res.locals.googleAuthEnabled = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
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

function requireAuth(req, res, next) {
  if (!res.locals.currentUser) {
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
  await renderPage(res, "home", {
    featuredMods,
    newestMods,
    totalMods: mods.length,
    totalCreators: new Set(mods.map((mod) => mod.authorId)).size,
  }, next);
});

app.get("/mods", async (req, res, next) => {
  const query = (req.query.q || "").trim().toLowerCase();
  const game = (req.query.game || "").trim();
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

  await renderPage(res, "mods", {
    mods,
    query,
    game,
  }, next);
});

app.get("/mods/:slug", async (req, res, next) => {
  const rawMod = (await listMods()).find((entry) => entry.slug === req.params.slug);
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

app.post("/mods/:slug/download", async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.slug === req.params.slug);
  if (!mod) {
    return res.status(404).render("not-found", { message: "That mod does not exist yet." });
  }

  mod.downloadCount += 1;
  await saveMods(mods);
  res.redirect(await getModDownloadUrl(mod.filePath || mod.fileName));
});

app.post("/mods/:slug/comments", requireAuth, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.slug === req.params.slug);
  const content = (req.body.content || "").trim();

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

app.get("/register", async (_req, res, next) => {
  await renderPage(res, "register", {}, next);
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const normalizedEmail = (email || "").trim().toLowerCase();
  const cleanUsername = (username || "").trim();
  const users = await listUsers();

  if (!cleanUsername || !normalizedEmail || !password) {
    req.session.notice = "Fill out every field to create an account.";
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

  users.push(user);
  await saveUsers(users);
  req.session.userId = user.id;
  try {
    await sendWelcomeEmail(user);
    req.session.notice = "Your modify.at account is live. Welcome email sent.";
  } catch (error) {
    console.error("Failed to send welcome email:", error.message);
    req.session.notice = "Your modify.at account is live. Email delivery needs SMTP setup.";
  }
  res.redirect("/dashboard");
});

app.get("/login", async (_req, res, next) => {
  await renderPage(res, "login", {}, next);
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = (email || "").trim().toLowerCase();
  const user = (await listUsers()).find((entry) => entry.email === normalizedEmail);

  if (!user || !user.passwordHash || !(await bcrypt.compare(password || "", user.passwordHash))) {
    req.session.notice = "We could not match that email and password.";
    return res.redirect("/login");
  }

  req.session.userId = user.id;
  req.session.notice = `Welcome back, ${user.username}.`;
  res.redirect("/dashboard");
});

app.get("/auth/google", (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    req.session.notice = "Google sign-in needs GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.";
    return res.redirect("/login");
  }

  res.redirect(createGoogleAuthUrl(req));
});

app.get("/auth/google/callback", async (req, res) => {
  if (!req.query.code || !req.query.state || req.query.state !== req.session.googleState) {
    req.session.notice = "Google sign-in could not be verified.";
    return res.redirect("/login");
  }

  try {
    const googleUser = await exchangeGoogleCode(req.query.code);
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
    hostedWithoutSupabase: isHostedWithoutSupabase(),
    commit: process.env.VERCEL_GIT_COMMIT_SHA || null,
  });
});

app.post("/upload/sign", requireAuth, async (req, res) => {
  if (!isSupabaseEnabled() || !getSupabaseEnv().anonKey) {
    return res.status(400).json({ error: "Supabase uploads are not configured." });
  }

  const originalFileName = (req.body.originalFileName || "").trim();
  const fileSize = Number(req.body.fileSize || 0);

  if (!originalFileName || !fileSize) {
    return res.status(400).json({ error: "Missing file information." });
  }

  const uploadId = makeId("upload");
  const signedUpload = await createSignedModUpload(originalFileName, uploadId);
  const uploadToken = signPayload({
    uploadId,
    fileName: signedUpload.fileName,
    filePath: signedUpload.filePath,
    originalFileName,
    fileSize,
    createdAt: Date.now(),
  });

  res.json({
    ...signedUpload,
    uploadToken,
  });
});

app.post("/upload/complete", requireAuth, async (req, res) => {
  const { title, gameSlug, category, version, summary, description, uploadToken } = req.body;
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

app.post("/upload", requireAuth, upload.single("modFile"), async (req, res) => {
  if (isHostedWithoutSupabase()) {
    req.session.notice = "Uploads need Supabase environment variables on Vercel.";
    return res.redirect("/upload");
  }

  const { title, gameSlug, category, version, summary, description } = req.body;
  const game = await getGameBySlug(gameSlug);

  if (!title || !gameSlug || !category || !version || !summary || !description || !req.file) {
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

  const uploadedFile = await uploadModFile(req.file, slug);
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
    originalFileName: req.file.originalname,
    fileSize: req.file.size,
    downloadCount: 0,
    verificationStatus: "unverified",
    authorId: res.locals.currentUser.id,
    authorName: res.locals.currentUser.username,
    createdAt: new Date().toISOString(),
  };

  mods.push(mod);
  await saveMods(mods);
  req.session.notice = "Your mod is now published as Unverified.";
  res.redirect(`/mods/${mod.slug}`);
});

app.get("/admin", requireAdmin, async (_req, res, next) => {
  const users = (await listUsers()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const mods = (await Promise.all((await listMods()).map(normalizeMod))).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const games = (await listGames()).sort((a, b) => a.name.localeCompare(b.name));

  await renderPage(res, "admin", {
    users,
    mods,
    games,
  }, next);
});

app.post("/admin/games", requireAdmin, async (req, res) => {
  const name = (req.body.name || "").trim();
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

app.post("/admin/games/:slug/categories", requireAdmin, async (req, res) => {
  const categoryName = (req.body.categoryName || "").trim();
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
  req.session.notice = `${categoryName} added to ${game.name}.`;
  res.redirect("/admin");
});

app.post("/admin/mods/:id/verify", requireAdmin, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.id === req.params.id);
  if (!mod) {
    req.session.notice = "Mod not found.";
    return res.redirect("/admin");
  }

  mod.verificationStatus = "safe";
  await saveMods(mods);
  req.session.notice = `${mod.title} is now marked Safe.`;
  res.redirect("/admin");
});

app.post("/admin/mods/:id/unverify", requireAdmin, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.id === req.params.id);
  if (!mod) {
    req.session.notice = "Mod not found.";
    return res.redirect("/admin");
  }

  mod.verificationStatus = "unverified";
  await saveMods(mods);
  req.session.notice = `${mod.title} is now marked Unverified.`;
  res.redirect("/admin");
});

app.post("/admin/mods/:id/delete", requireAdmin, async (req, res) => {
  const mods = await listMods();
  const mod = mods.find((entry) => entry.id === req.params.id);
  if (!mod) {
    req.session.notice = "Mod not found.";
    return res.redirect("/admin");
  }

  await deleteModFile(mod.filePath || mod.fileName);
  await deleteModById(req.params.id);
  req.session.notice = `${mod.title} has been removed.`;
  res.redirect("/admin");
});

app.post("/admin/users/:id/delete", requireAdmin, async (req, res) => {
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
  await Promise.all(userMods.map((mod) => deleteModFile(mod.filePath || mod.fileName)));
  await Promise.all(userMods.map((mod) => deleteModById(mod.id)));

  await deleteUserById(user.id);
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
