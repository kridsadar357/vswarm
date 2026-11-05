// Fixed-size character grid that renders to one ANSI frame.
// Each cell holds one visible glyph plus any combining marks (Thai vowels and tone marks).

export type Style = { fg?: string; bg?: string; bold?: boolean; dim?: boolean };

const COMBINING = /\p{M}/u;

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

/** Visible width of a string, treating combining marks as zero width. */
export function width(text: string): number {
  let n = 0;
  for (const ch of text) if (!COMBINING.test(ch)) n++;
  return n;
}

/** Cut to at most `max` visible columns, adding an ellipsis when cut. */
export function clip(text: string, max: number): string {
  if (width(text) <= max) return text;
  let out = "";
  let n = 0;
  for (const ch of text) {
    if (!COMBINING.test(ch)) {
      if (n === max - 1) break;
      n++;
    }
    out += ch;
  }
  return out + "…";
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

  put(x: number, y: number, text: string, style?: Style): number {
    if (y < 0 || y >= this.h) return x;
    let cx = x;
    for (const ch of text) {
      if (COMBINING.test(ch)) {
        if (cx - 1 >= 0 && cx - 1 < this.w) this.chars[y][cx - 1] += ch;
        continue;
      }
      if (cx >= 0 && cx < this.w) {
        this.chars[y][cx] = ch;
        this.styles[y][cx] = style;
        if (style?.bg) this.bgs[y][cx] = style.bg;
      }
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

  /** ANSI frame, cut to the terminal size so rows never wrap. */
  toString(cols = this.w, lines = this.h): string {
    const rows: string[] = [];
    for (let y = 0; y < Math.min(this.h, lines); y++) {
      let row = "";
      let last: string | null = null;
      for (let x = 0; x < Math.min(this.w, cols); x++) {
        const s = this.cell(x, y);
        const key = JSON.stringify(s ?? null);
        if (key !== last) {
          row += sgr(s);
          last = key;
        }
        row += this.chars[y][x];
      }
      rows.push(row + "\x1b[0m\x1b[K");
    }
    return rows.join("\n");
  }

  /** HTML spans with inline colours, for README images. */
  html(): string {
    const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    return this.chars
      .map((row, y) =>
        row
          .map((ch, x) => {
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
