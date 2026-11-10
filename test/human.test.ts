// Commands that weaken protection ask a person first (src/sec/human.ts). Nothing here shows a real dialog or reads a
// real answer: the terminal and the desktop are stand-ins, and the "real home" is a made-up path.
import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { agentSaysSo, confirmWeakening, realHome, shown, touchesRealHome, type Asker } from "../src/sec/human";

const REAL = "/Users/someone";
const atHome = { HOME: REAL };

/** A stand-in for the terminal and the desktop that records what was asked. */
function asker(terminal: string, desktop: boolean, canDesktop = true) {
  const asked: string[] = [];
  const io: Asker = {
    terminal: async (q) => (asked.push(`terminal: ${q}`), terminal),
    desktop: async (q) => (asked.push(`desktop: ${q}`), desktop),
    canDesktop: () => canDesktop,
  };
  return { io, asked };
}

describe("the question", () => {
  test("names the command, printable and short", () => {
    expect(shown("guard", ["off"])).toBe("vswarm guard off");
    expect(shown("ok", ["1\x1b[2J", "x".repeat(400)]).length).toBeLessThanOrEqual(200);
    expect(shown("ok", ["1\x1b[2J"])).not.toContain("\x1b");
  });
});

describe("asking a person", () => {
  test("a terminal a person is at: asked there; yes goes ahead, anything else is refused", async () => {
    const yes = asker("y", false);
    await confirmWeakening("vswarm guard off", { env: atHome, tty: true, io: yes.io, real: REAL });
    expect(yes.asked).toEqual([expect.stringMatching(/^terminal: vswarm guard off/)]);
    for (const a of ["", "n", "no", "yes please"]) {
      const no = asker(a, true);
      await expect(confirmWeakening("vswarm guard off", { env: atHome, tty: true, io: no.io, real: REAL })).rejects.toThrow("needs a person");
    }
  });

  test("an agent, or no terminal: the desktop dialog, never the terminal; refused there is refused", async () => {
    for (const [env, tty] of [[{ ...atHome, CLAUDECODE: "1" }, true], [atHome, false]] as const) {
      const ok = asker("y", true);
      await confirmWeakening("vswarm unlock", { env, tty, io: ok.io, real: REAL });
      expect(ok.asked).toEqual([expect.stringMatching(/^desktop: .*vswarm unlock/s)]);
      const no = asker("y", false);
      await expect(confirmWeakening("vswarm unlock", { env, tty, io: no.io, real: REAL })).rejects.toThrow("If you are an AI agent");
    }
  });

  test("nobody to ask: refused, and told to run it in a terminal", async () => {
    const none = asker("y", true, false);
    await expect(confirmWeakening("vswarm uninstall", { env: atHome, tty: false, io: none.io, real: REAL })).rejects.toThrow("Run it yourself in a terminal");
    expect(none.asked).toEqual([]);
  });

  test("a run that changes nothing in the real home (tests, a scratch scan) is not asked about", async () => {
    const never: Asker = { terminal: async () => { throw new Error("asked"); }, desktop: async () => { throw new Error("asked"); }, canDesktop: () => true };
    const scratch = { HOME: "/tmp/scratch", VSWARM_SEC_DIR: "/tmp/scratch/sec" };
    await confirmWeakening("vswarm baseline", { env: scratch, tty: false, io: never, real: REAL });
    // One vswarm folder in the real home is enough to ask; so is not knowing where the real home is.
    expect(await touchesRealHome({ ...scratch, VSWARM_SEC_DIR: `${REAL}/.vswarm/sec` }, REAL)).toBe(true);
    expect(await touchesRealHome({ ...scratch, VSWARM_HOME: `${REAL}/.vswarm` }, REAL)).toBe(true);
    expect(await touchesRealHome(atHome, REAL)).toBe(true);
    expect(await touchesRealHome({ HOME: `${REAL}/sub` }, REAL)).toBe(true);
    expect(await touchesRealHome({ HOME: `${REAL}2` }, REAL)).toBe(false);
  });

  test("agents that say who they are", () => {
    expect(agentSaysSo({ CLAUDECODE: "1" })).toBe(true);
    expect(agentSaysSo({ GEMINI_CLI: "1" })).toBe(true);
    expect(agentSaysSo({ HOME: "/h" })).toBe(false);
  });
});

describe.skipIf(process.platform === "win32")("the real home", () => {
  test("comes from the system's user database, not from HOME", async () => {
    const r = await realHome();
    expect(r && existsSync(r)).toBe(true);
    const prev = process.env.HOME;
    process.env.HOME = "/tmp/not-home";
    try {
      expect(await realHome()).toBe(r);
    } finally {
      process.env.HOME = prev;
    }
  });
});
