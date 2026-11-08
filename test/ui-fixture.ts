// A fake machine for vswarm ui tests and screenshots, built from the selftest's clean home: everything in one temp
// folder (home, Homebrew, state, agent), the sealing key in a file there. Nothing outside it is read or written,
// except the Windows snapshot, which is the selftest's fake one.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { run, type Ctx } from "../src/sec/ctx";
import { check } from "../src/sec/engine";
import { forBaseline, scan } from "../src/sec/scan";
import { CASES, plantClean, type Fake } from "../src/sec/selftest-cases";
import { files, saveBaseline, useKeyStore, writePrivate } from "../src/sec/store";

export interface FakeMachine {
  root: string;
  home: string;
  sec: string;
  agent: string;
  ctx: Ctx;
  fake: Fake;
}

/** Points vswarm's state at `root` and builds a clean machine with a baseline; `before` adds to it before the baseline. */
export async function fakeMachine(root: string, opt: { before?: (home: string) => void; agentDir?: string; windows?: boolean } = {}): Promise<FakeMachine> {
  const home = join(root, "home"), brew = join(root, "brew"), sec = join(root, "sec"), agent = opt.agentDir ?? join(root, "agent");
  for (const d of [home, brew]) mkdirSync(d, { recursive: true });
  process.env.VSWARM_SEC_DIR = sec;
  process.env.VSWARM_AGENT_DIR = agent;
  useKeyStore(undefined);
  const fake: Fake = { home, brew, win: {} };
  plantClean(fake);
  opt.before?.(home);
  const ctx: Ctx = {
    home, brew, pathDirs: [join(home, ".local/bin")], system: false, host: "dev-mbp", user: "tester",
    run: (cmd, t) => (cmd[0] === "crontab" ? Promise.resolve(fake.crontab) : ["plutil", "codesign"].includes(cmd[0]) ? run(cmd, t) : Promise.resolve(undefined)),
    win: opt.windows === false ? undefined : async () => structuredClone(fake.win),
  };
  await saveBaseline(forBaseline(await scan(ctx, { live: false })));
  writePrivate(files.osv(), {});
  return { root, home, sec, agent, ctx, fake };
}

/** Plants selftest cases by name. */
export function plant(m: FakeMachine, ...names: string[]) {
  for (const n of names) {
    const c = CASES.find((x) => x.name === n);
    if (!c) throw new Error(`no selftest case "${n}"`);
    c.plant(m.home, join(m.root, "brew"), m.fake.win, m.fake);
  }
}

export const writeAt = (path: string, text: string) => {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, text);
};

export const checkNow = (m: FakeMachine) => check(m.ctx, { offline: true });
