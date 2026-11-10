// The worm beside a check's headline (src/sec/mascot.ts): drawn only where it cannot get in the way, the same size in
// every state, and made of colour codes that clean() lets through and nothing else.
import { describe, expect, test } from "bun:test";
import { MASCOT_COLS, mascot, mascotMode } from "../src/sec/mascot";
import { cells, clean } from "../src/sec/print";

describe("the worm", () => {
  test("left out without colour, in a narrow terminal, or with VSWARM_MASCOT=0; 256 colours only where TERM says so", () => {
    expect(mascotMode(0, 120, {})).toBe(0);
    expect(mascotMode(24, 69, {})).toBe(0);
    expect(mascotMode(24, 0, {})).toBe(0);
    expect(mascotMode(24, 120, { VSWARM_MASCOT: "0" })).toBe(0);
    expect(mascotMode(24, 120, {})).toBe(24);
    expect(mascotMode(16, 120, { TERM: "xterm-256color" })).toBe(256);
    expect(mascotMode(16, 120, { TERM: "xterm" })).toBe(0);
    expect(mascot("pass", 0)).toEqual([]);
  });

  test("every state is the same size, fits its columns, and passes through clean() unchanged", () => {
    const sizes = new Set<number>();
    for (const v of ["pass", "warn", "block"] as const) for (const mode of [24, 256] as const) {
      const art = mascot(v, mode);
      sizes.add(art.length);
      for (const l of art) {
        expect(cells(l)).toBeLessThanOrEqual(MASCOT_COLS);
        expect(clean(l)).toBe(l);
        expect(l.replace(/\x1b\[[0-9;]*m/g, "")).toMatch(/^[ ▀▄]*$/);
      }
    }
    expect([...sizes]).toEqual([9]);
    // Each state has its own face.
    expect(mascot("pass", 24).join()).not.toBe(mascot("block", 24).join());
  });

  test("clean() still drops cursor moves and erases, background colours or not", () => {
    expect(clean("a\x1b[2Jb\x1b[1Ac")).toBe("a[2Jb[1Ac");
    expect(clean("\x1b[48;2;1;2;3mx\x1b[0m")).toBe("\x1b[48;2;1;2;3mx\x1b[0m");
    expect(clean("\x1b[38;5;99;48;5;16m▀\x1b[0m")).toBe("\x1b[38;5;99;48;5;16m▀\x1b[0m");
  });
});
