// Fixed-size character grid that renders to one ANSI frame.
// Each cell holds one visible glyph plus any combining marks (Thai vowels and tone marks).
// Wide glyphs (CJK, emoji) take two cells; the second holds "" and is skipped when drawing.

export type Style = { fg?: string; bg?: string; bold?: boolean; dim?: boolean };

/** Zero-width: combining marks (Thai vowels above/below, tone marks) and format characters (ZWJ, ZWSP). */
const ZERO = /[\p{M}\p{Cf}]/u;
/** Two columns wide: East Asian wide/fullwidth and emoji shown as emoji. */
const WIDE = /[\u1100-\u115F\u231A\u231B\u23E9-\u23EC\u23F0\u23F3\u25FD\u25FE\u2614\u2615\u2648-\u2653\u267F\u2693\u26A1\u26AA\u26AB\u26BD\u26BE\u26C4\u26C5\u26CE\u26D4\u26EA\u26F2-\u26F5\u26FA\u26FD\u2705\u270A\u270B\u2728\u274C\u274E\u2753-\u2755\u2757\u2795-\u2797\u27B0\u27BF\u2B1B\u2B1C\u2B50\u2B55\u2E80-\u303E\u3041-\u33FF\u3400-\u4DBF\u4E00-\u9FFF\uA000-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE30-\uFE4F\uFF00-\uFF60\uFFE0-\uFFE6\u{1F004}\u{1F0CF}\u{1F18E}\u{1F191}-\u{1F19A}\u{1F200}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{1F7E0}-\u{1F7EB}\u{1F90C}-\u{1F9FF}\u{1FA70}-\u{1FAFF}\u{20000}-\u{3FFFD}]/u;

/** Columns one character takes in a terminal: 0, 1 or 2. */
export function charWidth(ch: string): number {
  if (ZERO.test(ch)) return 0;
  return WIDE.test(ch) ? 2 : 1;
}

/** Tabs become spaces; other control characters would move the terminal's cursor, so they go. */
function clean(text: string): string {
  return text.replace(/\t/g, " ").replace(/[\x00-\x1f\x7f]/g, "");
}

function sgr(s: Style | undefined): string {
  if (!s) return "\x1b[0m";
  const parts = ["0"];
  if (s.bold) parts.push("1");
  if (s.dim) parts.push("2");
  if (s.fg) parts.push(`38;2;${hex(s.fg)}`);
  if (s.bg) parts.push(`48;2;${hex(s.bg)}`);
  return `\x1b[${parts.join(";")}m`;
}

function hex(c: string): string {
  const n = parseInt(c.replace("#", ""), 16);
  return `${(n >> 16) & 255};${(n >> 8) & 255};${n & 255}`;
}

/** Visible width of a string in terminal columns. */
export function width(text: string): number {
  let n = 0;
  for (const ch of text) n += charWidth(ch);
  return n;
}

/** Cut to at most `max` visible columns, adding an ellipsis when cut. */
export function clip(text: string, max: number): string {
  if (width(text) <= max) return text;
  let out = "";
  let n = 0;
  for (const ch of text) {
    const w = charWidth(ch);
    if (n + w > max - 1) break;
    n += w;
    out += ch;
  }
  return out + "…";
}

const WORDS = new Intl.Segmenter("th", { granularity: "word" });

/** Word-wrap to `max` columns. Thai has no spaces, so words come from the segmenter; over-long words are cut. */
export function wrap(text: string, max: number): string[] {
  const out: string[] = [];
  for (const para of text.split("\n")) {
    let line = "";
    for (const { segment } of WORDS.segment(para)) {
      let seg = segment;
      while (width(line) + width(seg) > max) {
        if (line.trim()) {
          out.push(line.trimEnd());
          line = "";
          seg = seg.trimStart();
          continue;
        }
        // A single word wider than the line: cut it.
        let head = "";
        for (const ch of seg) {
          if (width(head + ch) > max) break;
          head += ch;
        }
        out.push(head);
        seg = seg.slice(head.length);
      }
      line += line ? seg : seg.trimStart();
    }
    out.push(line.trimEnd());
  }
  return out;
}

export class Screen {
  private chars: string[][];
  private styles: (Style | undefined)[][];
  /** Background layer, separate so text drawn later keeps the panel colour under it. */
  private bgs: (string | undefined)[][];

  constructor(readonly w: number, readonly h: number) {
    this.chars = Array.from({ length: h }, () => Array(w).fill(" "));
    this.styles = Array.from({ length: h }, () => Array(w).fill(undefined));
    this.bgs = Array.from({ length: h }, () => Array(w).fill(undefined));
  }

  private cell(x: number, y: number): Style | undefined {
    const s = this.styles[y][x], bg = this.bgs[y][x];
    return bg ? { ...s, bg } : s;
  }

  fill(x: number, y: number, w: number, h: number, bg: string) {
    for (let r = y; r < y + h; r++)
      for (let c = x; c < x + w; c++) if (r >= 0 && r < this.h && c >= 0 && c < this.w) this.bgs[r][c] = bg;
  }

  /** One cell, keeping wide glyphs whole: overwriting either half of one blanks the other half. */
  private set(x: number, y: number, ch: string, style?: Style) {
    if (x < 0 || x >= this.w) return;
    const row = this.chars[y];
    if (row[x] === "" && x > 0) row[x - 1] = " ";
    if (x + 1 < this.w && row[x + 1] === "" && charWidth([...row[x]][0] ?? " ") === 2) row[x + 1] = " ";
    row[x] = ch;
    this.styles[y][x] = style;
    if (style?.bg) this.bgs[y][x] = style.bg;
  }

  put(x: number, y: number, text: string, style?: Style): number {
    if (y < 0 || y >= this.h) return x;
    let cx = x;
    for (const ch of clean(text)) {
      const w = charWidth(ch);
      if (w === 0) {
        if (cx - 1 >= 0 && cx - 1 < this.w && this.chars[y][cx - 1] !== "") this.chars[y][cx - 1] += ch;
        continue;
      }
      if (w === 2) {
        // No room for the second half at the right edge: show a space instead.
        if (cx + 1 >= this.w) {
          this.set(cx, y, " ", style);
        } else {
          this.set(cx, y, ch, style);
          this.set(cx + 1, y, "", style);
        }
        cx += 2;
        continue;
      }
      this.set(cx, y, ch, style);
      cx++;
    }
    return cx;
  }

  center(x: number, w: number, y: number, text: string, style?: Style) {
    const t = clip(text, w);
    this.put(x + Math.floor((w - width(t)) / 2), y, t, style);
  }

  /** Several differently styled pieces centred as one line. */
  centerRuns(x: number, w: number, y: number, runs: [string, Style?][]) {
    const total = runs.reduce((n, [t]) => n + width(t), 0);
    let cx = x + Math.max(0, Math.floor((w - total) / 2));
    for (const [t, s] of runs) cx = this.put(cx, y, t, s);
  }

  box(x: number, y: number, w: number, h: number, style: Style) {
    this.put(x, y, "┌" + "─".repeat(w - 2) + "┐", style);
    for (let r = 1; r < h - 1; r++) {
      this.put(x, y + r, "│", style);
      this.put(x + w - 1, y + r, "│", style);
    }
    this.put(x, y + h - 1, "└" + "─".repeat(w - 2) + "┘", style);
  }

  /** Rounded panel with a title tab cut into the top edge. */
  panel(x: number, y: number, w: number, h: number, line: Style, title?: [string, Style][]) {
    this.put(x, y, "╭" + "─".repeat(w - 2) + "╮", line);
    for (let r = 1; r < h - 1; r++) {
      this.put(x, y + r, "│", line);
      this.put(x + w - 1, y + r, "│", line);
    }
    this.put(x, y + h - 1, "╰" + "─".repeat(w - 2) + "╯", line);
    if (title) {
      let cx = x + 2;
      for (const [t, s] of title) cx = this.put(cx, y, t, s);
    }
  }

  hline(x1: number, x2: number, y: number, ch: string, style?: Style) {
    for (let x = Math.min(x1, x2); x <= Math.max(x1, x2); x++) this.put(x, y, ch, style);
  }

  vline(x: number, y1: number, y2: number, ch: string, style?: Style) {
    for (let y = Math.min(y1, y2); y <= Math.max(y1, y2); y++) this.put(x, y, ch, style);
  }

  /**
   * ANSI frame, cut to the terminal size. Every row starts with an absolute cursor move, and the cursor is put
   * back in place after each Thai cluster or wide glyph, because terminals disagree on how far those move it;
   * without this a row can drift, wrap, and push every row below it out of place.
   */
  toString(cols = this.w, lines = this.h, inline = false): string {
    const rows: string[] = [];
    const wcol = Math.min(this.w, cols);
    for (let y = 0; y < Math.min(this.h, lines); y++) {
      let row = inline ? "" : `\x1b[${y + 1};1H`;
      let last: string | null = null;
      for (let x = 0; x < wcol; x++) {
        const ch = this.chars[y][x];
        if (ch === "") continue;
        const s = this.cell(x, y);
        const key = JSON.stringify(s ?? null);
        if (key !== last) {
          row += sgr(s);
          last = key;
        }
        const wide = charWidth([...ch][0]) === 2;
        if (wide && x + 1 >= wcol) {
          row += " ";
          continue;
        }
        row += ch;
        const next = x + (wide ? 2 : 1);
        if ((wide || ch.length > 1) && next < wcol) row += `\x1b[${next + 1}G`;
      }
      rows.push(row + "\x1b[0m\x1b[K");
    }
    return rows.join(inline ? "\n" : "");
  }

  /** HTML spans with inline colours, for README images. */
  html(): string {
    const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    return this.chars
      .map((row, y) =>
        row
          .map((ch, x) => {
            if (ch === "") return "";
            const s = this.cell(x, y);
            if (!s) return esc(ch);
            const css = [s.fg && `color:${s.fg}`, s.bg && `background:${s.bg}`, s.bold && "font-weight:700", s.dim && "opacity:.6"].filter(Boolean).join(";");
            return `<span style="${css}">${esc(ch)}</span>`;
          })
          .join(""),
      )
      .join("\n");
  }

  /** Text only, for tests and snapshots. */
  plain(): string {
    return this.chars.map((r) => r.join("").trimEnd()).join("\n");
  }
}
