// The vswarm worm beside a check's headline: helmet with the V, cape, and a face for the state (a grin when safe, one
// raised brow for "check this", a frown for "stop"). Pixel art drawn two rows per line with ▀ (top pixel as the
// colour, bottom pixel as the background), so it needs 24-bit or 256 colours. It is left out wherever it would get in
// the way: no colour, a pipe or file, a terminal under 70 columns, or VSWARM_MASCOT=0.

import type { Verdict } from "./types";

const PAL: Record<string, [number, number, number]> = {
  D: [58, 44, 110], d: [92, 70, 160], O: [242, 140, 40], P: [160, 110, 230], p: [120, 80, 200],
  W: [250, 248, 240], K: [20, 18, 30], C: [240, 220, 190],
};

const HEAD = [
  "......dddddd......",
  "....dDDDDDDDDd....",
  "...dDOODDDDOODd...",
  "...dDDOODDOODDdOO.",
  "..dDDDDOOOODDDDdOO",
  "..dDDDDDOODDDDDd..",
];
const BODY = [
  ".....pPPPPPPpOOO..",
  "....CCpPPPPpOOOOO.",
  "...CCCpPPPPPpOOOO.",
  "...CCCCPPPPPPp.OO.",
  "....CCCCPPPPPPPp..",
  ".....CCCCCPPPPPPPp",
];
const FACE: Record<Verdict, string[]> = {
  pass: [
    "..pPKKPPPPPKKPp...",
    "..pPWKPPPPPKWPp...",
    "..pPPPPPPPPPPPp...",
    "...pPWPPPPPWPp....",
    "...pPPWWWWWPPp....",
  ],
  warn: [
    "..pPPPPPPPKKPPp...",
    "..pPWKPPPPPKWPp...",
    "..pPPPPPPPPPPPp...",
    "...pPPPPPPPPPp....",
    "...pPPPPKKKPPp....",
  ],
  block: [
    "..pKKPPPPPPPKKp...",
    "..pPWKKPPPKKWPp...",
    "..pPPPPPPPPPPPp...",
    "...pPPKKKKKPPp....",
    "...pPKPPPPPKPp....",
  ],
};

/** Columns the worm takes, with the gap after it. */
export const MASCOT_COLS = 18;

/** The nearest of the 256-colour cube's colours. */
const cube = ([r, g, b]: [number, number, number]) => 16 + 36 * Math.round((r / 255) * 5) + 6 * Math.round((g / 255) * 5) + Math.round((b / 255) * 5);

/** How the worm can be drawn here: 24-bit, 256 colours, or not at all. */
export function mascotMode(depth: 0 | 16 | 24, cols: number, env: Record<string, string | undefined> = process.env): 0 | 256 | 24 {
  if (env.VSWARM_MASCOT === "0" || depth === 0 || cols < 70) return 0;
  if (depth === 24) return 24;
  return /256/.test(env.TERM ?? "") ? 256 : 0;
}

/** The worm for a verdict, one string per terminal line (empty when mode is 0). */
export function mascot(v: Verdict, mode: 0 | 256 | 24): string[] {
  if (!mode) return [];
  const rows = [...HEAD, ...FACE[v], ...BODY];
  if (rows.length % 2) rows.push(".".repeat(MASCOT_COLS));
  const col = (ch: string, bg: boolean) => {
    const rgb = PAL[ch];
    return mode === 24 ? `${bg ? 48 : 38};2;${rgb.join(";")}` : `${bg ? 48 : 38};5;${cube(rgb)}`;
  };
  const out: string[] = [];
  for (let y = 0; y < rows.length; y += 2) {
    let l = "";
    for (let x = 0; x < MASCOT_COLS; x++) {
      const top = rows[y][x], bot = rows[y + 1][x];
      if (top === "." && bot === ".") l += " ";
      else if (bot === ".") l += `\x1b[${col(top, false)}m▀\x1b[0m`;
      else if (top === ".") l += `\x1b[${col(bot, false)}m▄\x1b[0m`;
      else l += `\x1b[${col(top, false)};${col(bot, true)}m▀\x1b[0m`;
    }
    out.push(l.replace(/ +$/, ""));
  }
  return out;
}
