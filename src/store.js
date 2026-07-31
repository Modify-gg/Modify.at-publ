const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { createClient } = require("@supabase/supabase-js");

const dataDir = path.join(__dirname, "..", "data");
const usersFile = path.join(dataDir, "users.json");
const modsFile = path.join(dataDir, "mods.json");
const gamesFile = path.join(dataDir, "games.json");
const reportsFile = path.join(dataDir, "reports.json");
const activityFile = path.join(dataDir, "activity.json");
const challengesFile = path.join(dataDir, "email-challenges.json");
const favoritesFile = path.join(dataDir, "favorites.json");
const followsFile = path.join(dataDir, "follows.json");
const notificationsFile = path.join(dataDir, "notifications.json");
const downloadEventsFile = path.join(dataDir, "download-events.json");
const uploadsDir = path.join(__dirname, "..", "uploads");

const adminSeed = {
  username: (process.env.ADMIN_USERNAME || "").trim(),
  email: (process.env.ADMIN_EMAIL || "").trim(),
  password: process.env.ADMIN_PASSWORD || "",
};

function hasAdminSeed() {
  return Boolean(adminSeed.username && adminSeed.email && adminSeed.password);
}

const defaultGames = [
  {
    id: "game_spaceflight-simulator",
    name: "Spaceflight Simulator",
    slug: "spaceflight-simulator",
    categories: ["Blueprints", "Mods", "Custom Parts"],
    createdAt: new Date().toISOString(),
  },
];

const supabaseUrl = (process.env.SUPABASE_URL || "").trim();
const supabaseServiceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
const bucketName = (process.env.SUPABASE_STORAGE_BUCKET || "mods").trim();
const hasSupabase = Boolean(
  /^https?:\/\/.+/.test(supabaseUrl) && supabaseServiceRoleKey
);
const supabase = hasSupabase
  ? createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: {
        persistSession: false,
      },
    })
  : null;

function isSupabaseEnabled() {
  return hasSupabase;
}

function isHostedWithoutSupabase() {
  return Boolean(process.env.VERCEL && !hasSupabase);
}

function ensureFile(filePath, fallback = "[]") {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, fallback, "utf8");
  }
}

function readJson(filePath, fallback = "[]") {
  ensureFile(filePath, fallback);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function toDbUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    password_hash: user.passwordHash || null,
    auth_provider: user.authProvider || "local",
    google_id: user.googleId || null,
    role: user.role || "user",
    bio: user.bio || "",
    created_at: user.createdAt || new Date().toISOString(),
  };
}

function fromDbUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    passwordHash: user.password_hash,
    authProvider: user.auth_provider,
    googleId: user.google_id,
    role: user.role,
    bio: user.bio || "",
    createdAt: user.created_at,
  };
}

function toDbGame(game) {
  return {
    id: game.id,
    name: game.name,
    slug: game.slug,
    categories: game.categories || [],
    icon_file_name: game.iconFileName || null,
    icon_file_path: game.iconFilePath || null,
    created_at: game.createdAt || new Date().toISOString(),
  };
}

function fromDbGame(game) {
  return {
    id: game.id,
    name: game.name,
    slug: game.slug,
    categories: game.categories || [],
    iconFileName: game.icon_file_name || null,
    iconFilePath: game.icon_file_path || null,
    createdAt: game.created_at,
  };
}

function toDbMod(mod) {
  const dbMod = {
    id: mod.id,
    slug: mod.slug,
    title: mod.title,
    game_slug: mod.gameSlug,
    category: mod.category,
    version: mod.version,
    summary: mod.summary,
    description: mod.description,
    file_name: mod.fileName,
    file_path: mod.filePath || mod.fileName,
    original_file_name: mod.originalFileName,
    file_size: mod.fileSize || 0,
    download_count: mod.downloadCount || 0,
    verification_status: mod.verificationStatus || "unverified",
    author_id: mod.authorId,
    author_name: mod.authorName,
    comments: mod.comments || [],
    platforms: Array.isArray(mod.platforms) ? mod.platforms : [],
    game_versions: Array.isArray(mod.gameVersions) ? mod.gameVersions : [],
    dependencies: Array.isArray(mod.dependencies) ? mod.dependencies : [],
    featured: Boolean(mod.featured),
    updated_at: mod.updatedAt || mod.createdAt || new Date().toISOString(),
    created_at: mod.createdAt || new Date().toISOString(),
  };

  dbMod.icon_file_name = mod.iconFileName || null;
  dbMod.icon_file_path = mod.iconFilePath || null;
  dbMod.gallery_images = Array.isArray(mod.galleryImages) ? mod.galleryImages : [];
  dbMod.install_instructions = mod.installInstructions || null;
  dbMod.changelog = Array.isArray(mod.changelog) ? mod.changelog : [];

  return dbMod;
}

function fromDbMod(mod) {
  return {
    id: mod.id,
    slug: mod.slug,
    title: mod.title,
    gameSlug: mod.game_slug,
    category: mod.category,
    version: mod.version,
    summary: mod.summary,
    description: mod.description,
    fileName: mod.file_name,
    filePath: mod.file_path,
    originalFileName: mod.original_file_name,
    fileSize: mod.file_size,
    downloadCount: mod.download_count,
    verificationStatus: mod.verification_status,
    authorId: mod.author_id,
    authorName: mod.author_name,
    comments: Array.isArray(mod.comments) ? mod.comments : [],
    platforms: Array.isArray(mod.platforms) ? mod.platforms : [],
    gameVersions: Array.isArray(mod.game_versions) ? mod.game_versions : [],
    dependencies: Array.isArray(mod.dependencies) ? mod.dependencies : [],
    featured: Boolean(mod.featured),
    updatedAt: mod.updated_at || mod.created_at,
    iconFileName: mod.icon_file_name || null,
    iconFilePath: mod.icon_file_path || null,
    galleryImages: Array.isArray(mod.gallery_images) ? mod.gallery_images : [],
    installInstructions: mod.install_instructions || "",
    changelog: Array.isArray(mod.changelog) ? mod.changelog : [],
    createdAt: mod.created_at,
  };
}

function fromDbReport(report) {
  return {
    id: report.id,
    modId: report.mod_id,
    modSlug: report.mod_slug,
    modTitle: report.mod_title,
    reporterId: report.reporter_id,
    reporterName: report.reporter_name,
    reason: report.reason,
    details: report.details,
    status: report.status,
    createdAt: report.created_at,
    resolvedAt: report.resolved_at,
    resolvedBy: report.resolved_by,
  };
}

function toDbReport(report) {
  return {
    id: report.id,
    mod_id: report.modId,
    mod_slug: report.modSlug,
    mod_title: report.modTitle,
    reporter_id: report.reporterId,
    reporter_name: report.reporterName,
    reason: report.reason,
    details: report.details || "",
    status: report.status || "open",
    created_at: report.createdAt || new Date().toISOString(),
    resolved_at: report.resolvedAt || null,
    resolved_by: report.resolvedBy || null,
  };
}

function fromDbActivity(entry) {
  return {
    id: entry.id,
    actorId: entry.actor_id,
    actorName: entry.actor_name,
    action: entry.action,
    targetType: entry.target_type,
    targetId: entry.target_id,
    details: entry.details,
    createdAt: entry.created_at,
  };
}

function toDbActivity(entry) {
  return {
    id: entry.id,
    actor_id: entry.actorId,
    actor_name: entry.actorName,
    action: entry.action,
    target_type: entry.targetType,
    target_id: entry.targetId,
    details: entry.details || "",
    created_at: entry.createdAt || new Date().toISOString(),
  };
}

function mapRecord(record, direction, table) {
  if (direction === "toDb") {
    if (table === "favorites") {
      return { id: record.id, user_id: record.userId, mod_id: record.modId, mod_slug: record.modSlug, mod_title: record.modTitle, created_at: record.createdAt || new Date().toISOString() };
    }
    if (table === "follows") {
      return { id: record.id, user_id: record.userId, creator_id: record.creatorId, creator_name: record.creatorName, created_at: record.createdAt || new Date().toISOString() };
    }
    if (table === "download_events") {
      return { id: record.id, mod_id: record.modId, creator_id: record.creatorId, created_at: record.createdAt || new Date().toISOString() };
    }
    return {
      id: record.id,
      user_id: record.userId || null,
      creator_id: record.creatorId || null,
      creator_name: record.creatorName || null,
      mod_id: record.modId || null,
      mod_slug: record.modSlug || null,
      mod_title: record.modTitle || null,
      type: record.type || null,
      title: record.title || null,
      message: record.message || null,
      read: Boolean(record.read),
      created_at: record.createdAt || new Date().toISOString(),
    };
  }
  return {
    id: record.id,
    userId: record.user_id,
    creatorId: record.creator_id,
    creatorName: record.creator_name,
    modId: record.mod_id,
    modSlug: record.mod_slug,
    modTitle: record.mod_title,
    type: record.type,
    title: record.title,
    message: record.message,
    read: Boolean(record.read),
    createdAt: record.created_at,
  };
}

function listLocal(file) {
  return readJson(file);
}

async function listRecords(table, file) {
  if (!supabase) return listLocal(file);
  const { data, error } = await supabase.from(table).select("*").order("created_at", { ascending: false });
  if (error) throw error;
  return data.map((entry) => mapRecord(entry, "fromDb"));
}

async function saveRecords(table, file, records) {
  if (!supabase) {
    writeJson(file, records.slice(-1000));
    return;
  }
  const { error } = await supabase.from(table).upsert(records.map((entry) => mapRecord(entry, "toDb", table)), { onConflict: "id" });
  if (error) throw error;
}

async function listFavorites() { return listRecords("favorites", favoritesFile); }
async function saveFavorites(records) { return saveRecords("favorites", favoritesFile, records); }
async function listFollows() { return listRecords("follows", followsFile); }
async function saveFollows(records) { return saveRecords("follows", followsFile, records); }
async function listNotifications() { return listRecords("notifications", notificationsFile); }
async function saveNotifications(records) { return saveRecords("notifications", notificationsFile, records); }

async function listDownloadEvents() { return listRecords("download_events", downloadEventsFile); }
async function saveDownloadEvents(records) { return saveRecords("download_events", downloadEventsFile, records); }

function fromDbChallenge(challenge) {
  return {
    id: challenge.id,
    email: challenge.email,
    purpose: challenge.purpose,
    codeHash: challenge.code_hash,
    payload: challenge.payload || {},
    attempts: challenge.attempts || 0,
    expiresAt: challenge.expires_at,
    createdAt: challenge.created_at,
  };
}

function toDbChallenge(challenge) {
  return {
    id: challenge.id,
    email: challenge.email,
    purpose: challenge.purpose,
    code_hash: challenge.codeHash,
    payload: challenge.payload || {},
    attempts: challenge.attempts || 0,
    expires_at: challenge.expiresAt,
    created_at: challenge.createdAt || new Date().toISOString(),
  };
}

async function listUsers() {
  if (!supabase) {
    return readJson(usersFile);
  }

  const { data, error } = await supabase.from("users").select("*");
  if (error) {
    throw error;
  }
  return data.map(fromDbUser);
}

async function saveUsers(users) {
  if (!supabase) {
    writeJson(usersFile, users);
    return;
  }

  const { error } = await supabase.from("users").upsert(users.map(toDbUser), { onConflict: "id" });
  if (error) {
    throw error;
  }
}

async function listMods() {
  if (!supabase) {
    return readJson(modsFile);
  }

  const { data, error } = await supabase.from("mods").select("*");
  if (error) {
    throw error;
  }
  return data.map(fromDbMod);
}

async function saveMods(mods) {
  if (!supabase) {
    writeJson(modsFile, mods);
    return;
  }

  const { error } = await supabase.from("mods").upsert(mods.map(toDbMod), { onConflict: "id" });
  if (error) {
    throw error;
  }
}

async function deleteModById(id) {
  if (!supabase) {
    const mods = readJson(modsFile);
    writeJson(modsFile, mods.filter((mod) => mod.id !== id));
    return;
  }

  const { error } = await supabase.from("mods").delete().eq("id", id);
  if (error) {
    throw error;
  }
}

async function deleteUserById(id) {
  if (!supabase) {
    const users = readJson(usersFile);
    writeJson(usersFile, users.filter((user) => user.id !== id));
    return;
  }

  const { error } = await supabase.from("users").delete().eq("id", id);
  if (error) {
    throw error;
  }
}

async function listGames() {
  if (!supabase) {
    return readJson(gamesFile);
  }

  const { data, error } = await supabase.from("games").select("*");
  if (error) {
    throw error;
  }
  return data.map(fromDbGame);
}

async function listReports() {
  if (!supabase) {
    return readJson(reportsFile);
  }

  const { data, error } = await supabase.from("reports").select("*").order("created_at", { ascending: false });
  if (error) throw error;
  return data.map(fromDbReport);
}

async function saveReports(reports) {
  if (!supabase) {
    writeJson(reportsFile, reports);
    return;
  }

  const { error } = await supabase.from("reports").upsert(reports.map(toDbReport), { onConflict: "id" });
  if (error) throw error;
}

async function listActivity() {
  if (!supabase) {
    return readJson(activityFile);
  }

  const { data, error } = await supabase.from("activity_log").select("*").order("created_at", { ascending: false }).limit(100);
  if (error) throw error;
  return data.map(fromDbActivity);
}

async function saveActivity(entries) {
  if (!supabase) {
    writeJson(activityFile, entries.slice(-100));
    return;
  }

  const { error } = await supabase.from("activity_log").upsert(entries.map(toDbActivity), { onConflict: "id" });
  if (error) throw error;
}

async function getEmailChallenge(id) {
  if (!id) return null;
  if (!supabase) {
    return readJson(challengesFile).find((challenge) => challenge.id === id) || null;
  }

  const { data, error } = await supabase.from("email_challenges").select("*").eq("id", id).maybeSingle();
  if (error) throw error;
  return data ? fromDbChallenge(data) : null;
}

async function saveEmailChallenge(challenge) {
  if (!supabase) {
    const challenges = readJson(challengesFile).filter((entry) => entry.id !== challenge.id);
    challenges.push(challenge);
    writeJson(challengesFile, challenges.slice(-100));
    return;
  }

  const { error } = await supabase.from("email_challenges").upsert(toDbChallenge(challenge), { onConflict: "id" });
  if (error) throw error;
}

async function deleteEmailChallenge(id) {
  if (!id) return;
  if (!supabase) {
    writeJson(challengesFile, readJson(challengesFile).filter((challenge) => challenge.id !== id));
    return;
  }

  const { error } = await supabase.from("email_challenges").delete().eq("id", id);
  if (error) throw error;
}

async function saveGames(games) {
  if (!supabase) {
    writeJson(gamesFile, games);
    return;
  }

  const { error } = await supabase.from("games").upsert(games.map(toDbGame), { onConflict: "id" });
  if (error) {
    throw error;
  }
}

function migrateUsers(users) {
  let changed = false;
  const nextUsers = users.map((user) => {
    const nextUser = { ...user };

    if (!nextUser.role) {
      nextUser.role = "user";
      changed = true;
    }

    if (!nextUser.authProvider) {
      nextUser.authProvider = "local";
      changed = true;
    }

    if (hasAdminSeed() && (
      nextUser.username === adminSeed.username ||
      nextUser.email.toLowerCase() === adminSeed.email.toLowerCase()
    )) {
      if (nextUser.role !== "admin") {
        nextUser.role = "admin";
        changed = true;
      }
    }

    return nextUser;
  });

  return { changed, users: nextUsers };
}

function migrateMods(mods, games) {
  let changed = false;
  const fallbackGame = games[0] || null;

  const nextMods = mods.map((mod) => {
    const nextMod = { ...mod };

    if (!nextMod.verificationStatus) {
      nextMod.verificationStatus = "unverified";
      changed = true;
    }

    if (!nextMod.gameSlug) {
      const matchingGame = games.find((game) => game.name.toLowerCase() === String(nextMod.game || "").toLowerCase());
      nextMod.gameSlug = matchingGame ? matchingGame.slug : fallbackGame ? fallbackGame.slug : "unknown-game";
      changed = true;
    }

    if (!nextMod.category) {
      nextMod.category = fallbackGame && fallbackGame.categories[0] ? fallbackGame.categories[0] : "General";
      changed = true;
    }

    if (!Array.isArray(nextMod.comments)) {
      nextMod.comments = [];
      changed = true;
    }

    if (!nextMod.filePath) {
      nextMod.filePath = nextMod.fileName;
      changed = true;
    }

    return nextMod;
  });

  return { changed, mods: nextMods };
}

async function ensureAdminUser(users) {
  if (!hasAdminSeed()) {
    return false;
  }

  const existing = users.find(
    (user) =>
      user.username === adminSeed.username ||
      user.email.toLowerCase() === adminSeed.email.toLowerCase()
  );

  if (existing) {
    let changed = false;
    if (existing.role !== "admin") {
      existing.role = "admin";
      changed = true;
    }
    if (!existing.passwordHash) {
      existing.passwordHash = await bcrypt.hash(adminSeed.password, 10);
      existing.authProvider = "local";
      changed = true;
    }
    return changed;
  }

  users.push({
    id: `user_admin_${Date.now()}`,
    username: adminSeed.username,
    email: adminSeed.email,
    passwordHash: await bcrypt.hash(adminSeed.password, 10),
    authProvider: "local",
    role: "admin",
    createdAt: new Date().toISOString(),
  });
  return true;
}

async function initializeStore() {
  if (!supabase) {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(uploadsDir, { recursive: true });
    ensureFile(usersFile);
    ensureFile(modsFile);
    ensureFile(reportsFile);
    ensureFile(activityFile);
  ensureFile(challengesFile);
  ensureFile(favoritesFile);
  ensureFile(followsFile);
  ensureFile(notificationsFile);
  ensureFile(downloadEventsFile);

    if (!fs.existsSync(gamesFile)) {
      writeJson(gamesFile, defaultGames);
    }
  }

  const usersMigration = migrateUsers(await listUsers());
  if ((await ensureAdminUser(usersMigration.users)) || usersMigration.changed) {
    await saveUsers(usersMigration.users);
  }

  const games = await listGames();
  if (!games.length) {
    await saveGames(defaultGames);
  }

  const modsMigration = migrateMods(await listMods(), await listGames());
  if (modsMigration.changed) {
    await saveMods(modsMigration.mods);
  }
}

async function uploadModFile(file, slug) {
  const ext = path.extname(file.originalname).toLowerCase();
  const safeName = `${Date.now()}-${slug}${ext || ".bin"}`;

  if (!supabase) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    fs.writeFileSync(path.join(uploadsDir, safeName), file.buffer);
    return {
      fileName: safeName,
      filePath: safeName,
    };
  }

  const filePath = `${slug}/${safeName}`;
  const { error } = await supabase.storage.from(bucketName).upload(filePath, file.buffer, {
    contentType: file.mimetype || "application/octet-stream",
    upsert: false,
  });

  if (error) {
    throw error;
  }

  return {
    fileName: safeName,
    filePath,
  };
}

async function createSignedModUpload(originalFileName, uploadId) {
  if (!supabase) {
    throw new Error("Supabase is not configured.");
  }

  return createSignedStoredUpload(originalFileName, uploadId, "mods", "mod-file");
}

async function createSignedStoredUpload(originalFileName, uploadId, folder, fallbackName) {
  if (!supabase) {
    throw new Error("Supabase is not configured.");
  }

  const ext = path.extname(originalFileName).toLowerCase();
  const safeBase = String(path.basename(originalFileName, ext))
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || fallbackName;
  const fileName = `${Date.now()}-${safeBase}${ext || ".bin"}`;
  const filePath = `uploads/${uploadId}/${folder}/${fileName}`;
  const { data, error } = await supabase.storage.from(bucketName).createSignedUploadUrl(filePath);

  if (error) {
    throw error;
  }

  return {
    fileName,
    filePath,
    token: data.token,
    signedUrl: data.signedUrl,
  };
}

async function createSignedAssetUpload(originalFileName, uploadId, kind) {
  return createSignedStoredUpload(originalFileName, uploadId, kind, "image");
}

async function deleteModFile(filePath) {
  if (!filePath) {
    return;
  }

  if (!supabase) {
    const localPath = path.join(uploadsDir, filePath);
    if (fs.existsSync(localPath)) {
      fs.unlinkSync(localPath);
    }
    return;
  }

  await supabase.storage.from(bucketName).remove([filePath]);
}

async function getModDownloadUrl(filePath, downloadName) {
  if (!supabase) {
    return `/uploads/${filePath}`;
  }

  const { data, error } = await supabase.storage
    .from(bucketName)
    .createSignedUrl(filePath, 60 * 10, {
      download: downloadName || true,
    });
  if (error) {
    throw error;
  }
  return data.signedUrl;
}

async function getModPreviewUrl(filePath) {
  if (!filePath) {
    return null;
  }

  if (!supabase) {
    return `/uploads/${filePath}`;
  }

  const { data, error } = await supabase.storage.from(bucketName).createSignedUrl(filePath, 60 * 60);
  if (error) {
    return null;
  }
  return data.signedUrl;
}

module.exports = {
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
  listFavorites,
  saveFavorites,
  listFollows,
  saveFollows,
  listNotifications,
  saveNotifications,
  listDownloadEvents,
  saveDownloadEvents,
  uploadModFile,
  createSignedModUpload,
  createSignedAssetUpload,
  deleteModFile,
  getModDownloadUrl,
  getModPreviewUrl,
};
