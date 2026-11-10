// Turns the terminal recordings from scenario.sh into the PNG screenshots in docs/img.
//   bun scripts/docs/render.ts <recordings folder> [docs/img]
// Each <name>.ansi (with <name>.cmd, the command as typed) becomes <name>.png: a terminal window, real colours.

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { findChrome } from "../../src/shot";

const [src, outArg = "docs/img"] = process.argv.slice(2);
if (!src) throw new Error("usage: bun scripts/docs/render.ts <recordings folder> [docs/img]");
const out = resolve(outArg);
mkdirSync(out, { recursive: true });
const chrome = findChrome();
if (!chrome) throw new Error("needs Chrome or Chromium");

const BASIC = ["#3b4252", "#ef6b6b", "#45c07a", "#e3a33a", "#4fb3d1", "#b48cff", "#4fd8e8", "#d6e2ea"];
const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** SGR colours (foreground and background) and bold/dim to spans; every other escape sequence is dropped. */
function toHtml(ansi: string): { html: string; lines: string[] } {
  const lines = ansi.replace(/\r\n/g, "\n").split("\n").map((l) => {
    // A line redrawn in place (progress bars): keep what was drawn last.
    const parts = l.split("\r").filter((p) => p.length);
    return parts.at(-1) ?? "";
  });
  while (lines.length && !lines.at(-1)!.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").trim()) lines.pop();
  while (lines.length && !lines[0].replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").trim()) lines.shift();
  let fg: string | undefined, bg: string | undefined, bold = false, dim = false;
  const html = lines.map((l) => {
    let o = "";
    let open = false;
    const flush = () => {
      if (open) o += "</span>";
      open = false;
      const st = [fg ? `color:${fg}` : "", bg ? `background:${bg}` : "", bold ? "font-weight:700" : "", dim ? "opacity:.62" : ""].filter(Boolean).join(";");
      if (st) (o += `<span style="${st}">`), (open = true);
    };
    for (const m of l.split(/(\x1b\[[0-9;?]*[A-Za-z])/)) {
      const sgr = /^\x1b\[([0-9;]*)m$/.exec(m);
      if (sgr) {
        const codes = (sgr[1] || "0").split(";").map(Number);
        for (let i = 0; i < codes.length; i++) {
          const k = codes[i];
          if (k === 0) (fg = bg = undefined), (bold = false), (dim = false);
          else if (k === 1) bold = true;
          else if (k === 2) dim = true;
          else if (k === 22) (bold = false), (dim = false);
          else if (k === 39) fg = undefined;
          else if (k >= 30 && k <= 37) fg = BASIC[k - 30];
          else if (k >= 90 && k <= 97) fg = BASIC[k - 90];
          else if (k === 49) bg = undefined;
          else if (k >= 40 && k <= 47) bg = BASIC[k - 40];
          else if ((k === 38 || k === 48) && codes[i + 1] === 2) {
            const rgb = `rgb(${codes[i + 2]},${codes[i + 3]},${codes[i + 4]})`;
            if (k === 38) fg = rgb;
            else bg = rgb;
            i += 4;
          }
        }
        flush();
        continue;
      }
      if (m.startsWith("\x1b")) continue;
      // Half blocks (the worm) as cells of exactly one line's height, so the pixels meet with no gap between lines.
      o += m.split(/([▀▄])/).map((x) => {
        if (x !== "▀" && x !== "▄") return esc(x);
        const [top, bottom] = x === "▀" ? [fg, bg] : [bg, fg];
        return `<i class="px" style="background:linear-gradient(${top ?? "transparent"} 50%,${bottom ?? "transparent"} 50%)"></i>`;
      }).join("");
    }
    if (open) o += "</span>";
    return o;
  }).join("\n");
  return { html, lines: lines.map((l) => l.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")) };
}

const WIDTH = 1040, CHARS = 116, LINE = 20.3;
const tmp = mkdtempSync(join(tmpdir(), "vswarm-docs-"));
const names = readdirSync(src).filter((f) => f.endsWith(".ansi")).map((f) => f.slice(0, -5)).filter((n) => !process.argv[4] || n === process.argv[4]);
for (const name of names) {
  const cmd = existsSync(join(src, `${name}.cmd`)) ? readFileSync(join(src, `${name}.cmd`), "utf8") : name;
  const { html, lines } = toHtml(readFileSync(join(src, `${name}.ansi`), "utf8"));
  const rows = 1 + lines.reduce((n, l) => n + Math.max(1, Math.ceil([...l].length / CHARS)), 0);
  const height = Math.ceil(rows * LINE + 34 + 44 + 4);
  const page = `<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;background:#0b1015}
.w{margin:0;background:#0d141a;border:1px solid #1f2b35;border-radius:10px;overflow:hidden;height:${height - 2}px;box-sizing:border-box}
.bar{height:34px;background:#141d25;display:flex;align-items:center;padding:0 14px;gap:8px;border-bottom:1px solid #1f2b35}
.d{width:12px;height:12px;border-radius:50%}.t{flex:1;text-align:center;color:#7f93a3;font:12px -apple-system,system-ui,sans-serif;margin-right:52px}
pre{margin:0;padding:14px 20px;font:13.5px/${LINE}px Menlo,"DejaVu Sans Mono",monospace;color:#d6e2ea;white-space:pre-wrap;word-break:break-all}
.p{color:#45c07a}
.px{display:inline-block;width:1ch;height:${LINE}px;vertical-align:top}
</style><div class="w"><div class="bar"><span class="d" style="background:#ff5f57"></span><span class="d" style="background:#febc2e"></span><span class="d" style="background:#28c840"></span><span class="t">dev@laptop — ${esc(cmd.slice(0, 80))}</span></div><pre><span class="p">$</span> ${esc(cmd)}\n${html}</pre></div>`;
  const file = join(tmp, `${name}.html`);
  writeFileSync(file, page);
  const png = join(out, `${name}.png`);
  const p = Bun.spawn([chrome, "--headless=new", "--disable-gpu", "--use-angle=swiftshader", "--hide-scrollbars", "--force-device-scale-factor=2",
    `--user-data-dir=${join(tmp, "profile")}`, `--window-size=${WIDTH},${height}`, `--screenshot=${png}`, pathToFileURL(file).href], { stdout: "ignore", stderr: "ignore" });
  await p.exited;
  // 96 colours are plenty for a terminal and keep the repository (which the installer clones) small.
  const magick = Bun.which("magick");
  if (magick && existsSync(png)) await Bun.spawn([magick, png, "-colors", "96", "-define", "png:compression-level=9", `PNG8:${png}`]).exited;
  console.log(`${existsSync(png) ? "✔" : "✖"} ${name}.png  ${rows} rows`);
}
rmSync(tmp, { recursive: true, force: true });
