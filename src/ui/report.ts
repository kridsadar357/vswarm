// `vswarm report --html [--out file]`: the dashboard as one self-contained HTML file, for sharing with a team. No
// server and no actions: the page's script, style, both language files and the data are inside the file, and its
// own CSP lets only that exact script and style run and nothing load from anywhere. Credentials are masked and home
// folders shown as ~ (state.ts), and the user name is left out.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { realCtx, type Ctx } from "../sec/ctx";
import { check } from "../sec/engine";
import { dashboard, type Dash } from "./state";

const DIR = import.meta.dir;
const read = (f: string) => readFileSync(join(DIR, f), "utf8");
const b64sha = (s: string) => createHash("sha256").update(s, "utf8").digest("base64");

/** JSON that is safe inside <script type="application/json">: nothing in it can close the element. */
export const scriptJson = (v: unknown) => JSON.stringify(v).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");

export function reportHtml(dash: Dash): string {
  const css = read("app.css");
  const js = read("app.js");
  const i18n = { en: JSON.parse(read("i18n/en.json")), th: JSON.parse(read("i18n/th.json")) };
  const csp = `default-src 'none'; script-src 'sha256-${b64sha(js)}'; style-src 'sha256-${b64sha(css)}'; img-src data:; base-uri 'none'; form-action 'none'`;
  let html = read("index.html")
    .replace('<html lang="en">', `<html lang="${dash.lang}">`)
    .replace('<meta charset="utf-8">', `<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="${csp}">`);
  // Function replacements: a $ in the script or style must stay a $.
  html = html.replace('<link rel="stylesheet" href="app.css">', () => `<style>${css}</style>`);
  html = html.replace('<script src="app.js" defer></script>', () => `<script id="vswarm-data" type="application/json">${scriptJson({ dash, i18n })}</script>\n<script>${js}</script>`);
  return html;
}

export async function htmlReport(opt: { out?: string; offline?: boolean; ctx?: Ctx; cwd?: string }): Promise<string> {
  const r = await check(opt.ctx ?? realCtx(), { offline: opt.offline });
  const dash = await dashboard({ home: opt.ctx?.home, mode: "report", notes: r.notes });
  dash.user = "";
  const stamp = new Date(dash.at).toISOString().slice(0, 16).replace(/[-:]/g, "").replace("T", "-");
  const file = resolve(opt.cwd ?? process.cwd(), opt.out ?? `vswarm-report-${(dash.host || "machine").replace(/[^A-Za-z0-9._-]/g, "_")}-${stamp}.html`);
  writeFileSync(file, reportHtml(dash), { mode: 0o600 });
  return file;
}
