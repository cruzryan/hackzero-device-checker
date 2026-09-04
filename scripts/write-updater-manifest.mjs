import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [releaseRoot] = process.argv.slice(2);
const tag = process.env.GITHUB_REF_NAME;
const repository = process.env.GITHUB_REPOSITORY;
if (!releaseRoot || !tag || !repository || !tag.startsWith("desktop-v")) {
  throw new Error("This script must run from a desktop-v* GitHub release workflow.");
}

const assets = {
  "windows-x86_64": ["desktop-windows", "HackZero-Device-Checker-windows-amd64.msi"],
  "darwin-aarch64": ["desktop-macos", "HackZero-Device-Checker-macos-arm64.app.tar.gz"],
  "linux-x86_64": ["desktop-debian", "hackzero-device-checker-linux-amd64.AppImage"],
};
const platforms = {};
for (const [target, [directory, filename]] of Object.entries(assets)) {
  const signature = (await readFile(join(releaseRoot, directory, `${filename}.sig`), "utf8")).trim();
  if (!signature) throw new Error(`Missing updater signature for ${target}.`);
  platforms[target] = {
    url: `https://github.com/${repository}/releases/download/${tag}/${filename}`,
    signature,
  };
}

await writeFile(join(releaseRoot, "latest.json"), `${JSON.stringify({
  version: tag.slice("desktop-v".length),
  notes: "Signed Device Checker update.",
  pub_date: new Date().toISOString(),
  platforms,
}, null, 2)}\n`);
