const fs = require("fs");
const path = require("path");
const { loadEnv } = require("../src/env");

loadEnv();

const {
  isSupabaseEnabled,
  saveUsers,
  saveGames,
  saveMods,
  uploadModFile,
} = require("../src/store");

const rootDir = path.join(__dirname, "..");
const dataDir = path.join(rootDir, "data");
const uploadsDir = path.join(rootDir, "uploads");

function readLocalJson(fileName) {
  const filePath = path.join(dataDir, fileName);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function guessMimeType(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  if (ext === ".zip") return "application/zip";
  if (ext === ".mp4") return "video/mp4";
  if (ext === ".png") return "image/png";
  if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  return "application/octet-stream";
}

async function main() {
  if (!isSupabaseEnabled()) {
    throw new Error("Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to .env before running this.");
  }

  const users = readLocalJson("users.json");
  const games = readLocalJson("games.json");
  const mods = readLocalJson("mods.json");

  for (const mod of mods) {
    const localFileName = mod.fileName || mod.filePath;
    const localFilePath = localFileName ? path.join(uploadsDir, localFileName) : null;

    if (localFilePath && fs.existsSync(localFilePath)) {
      const uploaded = await uploadModFile(
        {
          originalname: mod.originalFileName || localFileName,
          mimetype: guessMimeType(localFileName),
          buffer: fs.readFileSync(localFilePath),
        },
        mod.slug
      );

      mod.fileName = uploaded.fileName;
      mod.filePath = uploaded.filePath;
    }
  }

  await saveUsers(users);
  await saveGames(games);
  await saveMods(mods);

  console.log(`Migrated ${users.length} users, ${games.length} games, and ${mods.length} mods to Supabase.`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
