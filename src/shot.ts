// `vswarm shot`: a screenshot of a local page, so Claude can look at what it built.
// It runs outside the sandbox (Chrome needs its own profile and sockets), so it only ever opens
// localhost URLs or local files; anything else is refused.

import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const CHROMES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
];

export function findChrome(): string | undefined {
  if (process.env.CHROME && existsSync(process.env.CHROME)) return process.env.CHROME;
  for (const c of CHROMES) if (existsSync(c)) return c;
  for (const n of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    const p = Bun.which(n);
    if (p) return p;
  }
}

/** A local page as a URL, or undefined when the target is not on this machine. */
export function localTarget(target: string, cwd: string): string | undefined {
  if (/^https?:\/\//i.test(target)) {
    return /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)([:/?#]|$)/i.test(target) ? target.replace("0.0.0.0", "localhost") : undefined;
  }
  if (/^file:\/\//i.test(target)) return target;
  if (/^[a-z][\w+.-]*:/i.test(target)) return;
  const p = resolve(cwd, target);
  return existsSync(p) ? pathToFileURL(p).href : undefined;
}

export async function shot(target: string, out: string, opt: { size?: string; wait?: number; cwd?: string } = {}) {
  const url = localTarget(target, opt.cwd ?? process.cwd());
  if (!url) throw new Error(`vswarm shot only opens localhost URLs and local files, not ${target}`);
  const chrome = findChrome();
  if (!chrome) throw new Error("no Chrome, Chromium or Edge found (set CHROME=/path/to/chrome)");
  const [w, h] = (opt.size ?? "1280x800").split("x").map(Number);
  const profile = mkdtempSync(resolve(tmpdir(), "vswarm-shot-"));
  const file = resolve(opt.cwd ?? process.cwd(), out);
  try {
    // SwiftShader gives WebGL without a GPU, so three.js scenes render instead of coming out blank.
    const p = Bun.spawn([
      chrome, "--headless=new", "--hide-scrollbars", "--mute-audio", "--no-first-run", "--no-default-browser-check",
      "--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist",
      `--user-data-dir=${profile}`, `--window-size=${w || 1280},${h || 800}`,
      `--virtual-time-budget=${opt.wait ?? 5000}`, `--screenshot=${file}`, url,
    ], { stdout: "pipe", stderr: "pipe" });
    const timer = setTimeout(() => p.kill(), 60_000);
    const [, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    clearTimeout(timer);
    if (code !== 0 || !existsSync(file)) throw new Error(`Chrome could not take the screenshot (exit ${code}): ${err.trim().split("\n").slice(-2).join(" ")}`);
  } finally {
    rmSync(profile, { recursive: true, force: true });
  }
  return file;
}
