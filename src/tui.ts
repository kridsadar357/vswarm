// Full-screen terminal: alternate screen, a redraw loop and key input.

import { H, W } from "./view";

export type Key =
  | { name: "enter" | "backspace" | "esc" | "up" | "down" | "left" | "right" | "tab" | "ctrl-c" | "ctrl-d" | "ctrl-u" | "space" }
  | { name: "text"; text: string };

/** One stdin chunk to keys. A paste arrives as one chunk and stays one piece of text. */
export function parseKeys(chunk: string): Key[] {
  const named: Record<string, Key["name"]> = {
    "\r": "enter", "\n": "enter", "\x7f": "backspace", "\b": "backspace", "\x1b": "esc", "\t": "tab",
    "\x03": "ctrl-c", "\x04": "ctrl-d", "\x15": "ctrl-u", " ": "space",
    "\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left", "\x1bOA": "up", "\x1bOB": "down",
  };
  if (named[chunk]) return [{ name: named[chunk] } as Key];
  const keys: Key[] = [];
  let text = "";
  const flush = () => {
    if (text) keys.push({ name: "text", text });
    text = "";
  };
  for (let i = 0; i < chunk.length; i++) {
    const ch = chunk[i];
    if (ch === "\x1b") {
      // Skip any other escape sequence (function keys, mouse) rather than typing it.
      flush();
      const m = /^\x1b(\[[0-9;]*[A-Za-z~]|O[A-Za-z])/.exec(chunk.slice(i));
      if (m) {
        const k = named[m[0]];
        if (k) keys.push({ name: k } as Key);
        i += m[0].length - 1;
      } else keys.push({ name: "esc" });
    } else if (ch === "\x7f" || ch === "\b") {
      flush();
      keys.push({ name: "backspace" });
    } else if (ch === "\x03") {
      flush();
      keys.push({ name: "ctrl-c" });
    } else if (ch === "\r" || ch === "\n") {
      // Newlines inside a paste become spaces; a lone Enter was handled above.
      text += " ";
    } else if (ch >= " " || ch > "\x7f") text += ch;
  }
  flush();
  return keys;
}

const SEGMENTS = new Intl.Segmenter("th", { granularity: "grapheme" });

/** Drop the last character as the user sees it (a Thai consonant with its vowel and tone mark goes together). */
export function dropLast(s: string): string {
  const parts = [...SEGMENTS.segment(s)];
  parts.pop();
  return parts.map((p) => p.segment).join("");
}

export interface Board {
  stop(): void;
  /** Redraw now instead of waiting for the next tick. */
  kick(): void;
}

/** Draws `frame(cols, rows, n)` about 8 times a second and hands keys to `onKey`. */
export function board(frame: (cols: number, rows: number, n: number) => string, onKey: (k: Key) => void): Board {
  const out = process.stdout;
  out.write("\x1b[?1049h\x1b[?25l\x1b[2J");
  let n = 0;
  const render = () => {
    const cols = out.columns ?? W;
    const rows = out.rows ?? H;
    let text = frame(cols, rows, n++);
    if (cols < W || rows < H) {
      text += `\x1b[${Math.min(rows, H)};1H\x1b[0;30;43m terminal is ${cols}×${rows}; vswarm needs at least ${W}×${H} \x1b[0m`;
    }
    out.write("\x1b[H" + text);
  };
  const timer = setInterval(render, 120);
  render();
  const onResize = () => out.write("\x1b[2J");
  out.on("resize", onResize);
  const stdin = process.stdin;
  const onData = (b: Buffer) => {
    for (const k of parseKeys(b.toString("utf8"))) onKey(k);
    render();
  };
  if (stdin.isTTY) {
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  }
  const restore = () => out.write("\x1b[0m\x1b[?25h\x1b[?1049l");
  process.on("exit", restore);
  return {
    kick: render,
    stop() {
      clearInterval(timer);
      out.off("resize", onResize);
      if (stdin.isTTY) {
        stdin.off("data", onData);
        stdin.setRawMode(false);
        stdin.pause();
      }
      process.off("exit", restore);
      restore();
    },
  };
}
