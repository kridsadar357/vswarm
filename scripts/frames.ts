// Turns the HTML frames written by `v-swarm run --frames dir` into PNGs and an MP4.
// usage: bun scripts/frames.ts <frames dir> <out.mp4> [--fps 4] [--every 1]

import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const CHROME = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const args = process.argv.slice(2);
const opt = (name: string, d: number) => {
  const i = args.indexOf(name);
  return i >= 0 ? Number(args.splice(i, 2)[1]) : d;
};
const fps = opt("--fps", 4);
const every = opt("--every", 1);
const [dir, out] = args.map((a) => resolve(a));
if (!dir || !out) throw new Error("usage: bun scripts/frames.ts <frames dir> <out.mp4> [--fps 4] [--every 1]");

const frames = readdirSync(dir).filter((f) => /^frame-\d+\.html$/.test(f)).sort().filter((_, i) => i % every === 0);

async function shot(html: string, png: string) {
  const p = Bun.spawn([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
    "--window-size=860,850", `--screenshot=${png}`, `file://${html}`], { stdout: "ignore", stderr: "ignore" });
  await p.exited;
}

const POOL = 6;
let next = 0;
await Promise.all(Array.from({ length: POOL }, async () => {
  while (next < frames.length) {
    const i = next++;
    await shot(join(dir, frames[i]), join(dir, `png-${String(i).padStart(4, "0")}.png`));
  }
}));

const ff = Bun.spawn(["ffmpeg", "-y", "-loglevel", "error", "-framerate", String(fps), "-i", join(dir, "png-%04d.png"),
  "-vf", "scale=1720:-2", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "22", out], { stdout: "inherit", stderr: "inherit" });
process.exit(await ff.exited);
