const fs = require("fs");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

function loadEnv() {
  const envPath = path.join(__dirname, "..", ".env");
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, "");
  }
}

loadEnv();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const bucket = process.env.SUPABASE_STORAGE_BUCKET || "mods";
const steamAppIds = {
  "beamng-drive": 284160,
  besiege: 346010,
  bonelab: 1592190,
  "geometry-dash": 322170,
  "grand-theft-auto-v": 271590,
  "people-playground": 1118200,
  terraria: 105600,
  "spaceflight-simulator": 1718870,
};

function fallbackSvg(name) {
  const initial = name.slice(0, 1).toUpperCase();
  const safeName = name.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[character]));
  return `<svg xmlns="http://www.w3.org/2000/svg" width="245" height="245" viewBox="0 0 245 245"><rect width="245" height="245" fill="#102c35"/><circle cx="188" cy="48" r="72" fill="#63f5be" opacity=".22"/><text x="24" y="130" fill="#eef4ff" font-family="Arial,sans-serif" font-size="92" font-weight="700">${initial}</text><text x="24" y="210" fill="#9aabc4" font-family="Arial,sans-serif" font-size="16">${safeName.slice(0, 24)}</text></svg>`;
}

async function main() {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error("Supabase environment variables are missing.");
  const { data: games, error: gamesError } = await supabase.from("games").select("id,name,slug,icon_file_path");
  if (gamesError) throw gamesError;

  for (const game of games) {
    if (game.icon_file_path) {
      console.log(`Skipping ${game.name}: icon already exists.`);
      continue;
    }

    let buffer;
    let contentType;
    let extension;
    const appId = steamAppIds[game.slug];
    if (appId) {
      const response = await fetch(`https://cdn.cloudflare.steamstatic.com/steam/apps/${appId}/header.jpg`);
      if (response.ok) {
        buffer = Buffer.from(await response.arrayBuffer());
        contentType = "image/jpeg";
        extension = "jpg";
      }
    }
    if (!buffer) {
      buffer = Buffer.from(fallbackSvg(game.name));
      contentType = "image/svg+xml";
      extension = "svg";
    }

    const fileName = `seed-${game.slug}-${Date.now()}.${extension}`;
    const filePath = `games/${game.slug}/${fileName}`;
    const { error: uploadError } = await supabase.storage.from(bucket).upload(filePath, buffer, { contentType, upsert: false });
    if (uploadError) throw uploadError;
    const { error: updateError } = await supabase.from("games").update({ icon_file_name: fileName, icon_file_path: filePath }).eq("id", game.id);
    if (updateError) throw updateError;
    console.log(`Added ${game.name}.`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
