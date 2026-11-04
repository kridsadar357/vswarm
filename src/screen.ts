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

  constructor(readonly w: number, readonly h: number) {
    this.chars = Array.from({ length: h }, () => Array(w).fill(" "));
    this.styles = Array.from({ length: h }, () => Array(w).fill(undefined));
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
      let last: Style | undefined | null = null;
      for (let x = 0; x < Math.min(this.w, cols); x++) {
        const s = this.styles[y][x];
        if (s !== last) {
          row += sgr(s);
          last = s;
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
            const s = this.styles[y][x];
            if (!s) return esc(ch);
            const css = [s.fg && `color:${s.fg}`, s.bold && "font-weight:700", s.dim && "opacity:.6"].filter(Boolean).join(";");
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
