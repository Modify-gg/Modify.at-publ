const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const dataDir = path.join(__dirname, "..", "data");
const usersFile = path.join(dataDir, "users.json");
const modsFile = path.join(dataDir, "mods.json");
const gamesFile = path.join(dataDir, "games.json");

const adminSeed = {
  username: "UnknownTheReal1",
  email: "edricgarcia2020@yahoo.com",
  password: "Octubre2020",
};

const defaultGames = [
  {
    id: "game_spaceflight-simulator",
    name: "Spaceflight Simulator",
    slug: "spaceflight-simulator",
    categories: ["Blueprints", "Mods", "Custom Parts"],
    createdAt: new Date().toISOString(),
  },
];

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

function listUsers() {
  return readJson(usersFile);
}

function saveUsers(users) {
  writeJson(usersFile, users);
}

function listMods() {
  return readJson(modsFile);
}

function saveMods(mods) {
  writeJson(modsFile, mods);
}

function listGames() {
  return readJson(gamesFile);
}

function saveGames(games) {
  writeJson(gamesFile, games);
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

    if (
      nextUser.username === adminSeed.username ||
      nextUser.email.toLowerCase() === adminSeed.email.toLowerCase()
    ) {
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

    return nextMod;
  });

  return { changed, mods: nextMods };
}

function ensureAdminUser(users) {
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
      existing.passwordHash = bcrypt.hashSync(adminSeed.password, 10);
      existing.authProvider = "local";
      changed = true;
    }
    return changed;
  }

  users.push({
    id: `user_admin_${Date.now()}`,
    username: adminSeed.username,
    email: adminSeed.email,
    passwordHash: bcrypt.hashSync(adminSeed.password, 10),
    authProvider: "local",
    role: "admin",
    createdAt: new Date().toISOString(),
  });
  return true;
}

function initializeStore() {
  fs.mkdirSync(dataDir, { recursive: true });
  ensureFile(usersFile);
  ensureFile(modsFile);

  if (!fs.existsSync(gamesFile)) {
    writeJson(gamesFile, defaultGames);
  }

  const usersMigration = migrateUsers(listUsers());
  if (ensureAdminUser(usersMigration.users) || usersMigration.changed) {
    saveUsers(usersMigration.users);
  }

  const games = listGames();
  if (!games.length) {
    saveGames(defaultGames);
  }

  const finalGames = listGames();
  const modsMigration = migrateMods(listMods(), finalGames);
  if (modsMigration.changed) {
    saveMods(modsMigration.mods);
  }
}

module.exports = {
  initializeStore,
  listUsers,
  saveUsers,
  listMods,
  saveMods,
  listGames,
  saveGames,
};
