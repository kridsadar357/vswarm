// Updating vswarm itself, only to releases signed by a key you already trust.
//
// A security tool that pulls whatever is on GitHub is a way into every machine that runs it: whoever takes over the
// repository (or the maintainer's account) ships code to all of them at the next `vswarm update`. So:
//   · releases are git tags signed with the maintainer's SSH key (git tag -s, gpg.format=ssh)
//   · the first install pins the release keys listed in trust/allowed_signers (trust on first use)
//   · every later update verifies tags against the pinned file on this machine, never against the copy in the
//     repository; it takes the newest tag that verifies, ignores unsigned tags and tags signed by another key (so a
//     stray tag cannot block updates), and refuses a version older than this one
// Changing the release key therefore needs you: vswarm trust shows the pinned fingerprints.

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { HOME } from "../home";
import { exec, type Exec } from "./ctx";

export const PIN = () => process.env.VSWARM_TRUST_FILE ?? join(HOME, "trust", "allowed_signers");

async function git(root: string, args: string[], extra: string[] = []): Promise<Exec> {
  const r = await exec(["git", ...extra, "-C", root, ...args], { env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } });
  return { code: r.code, out: r.out.trim(), err: r.err.trim() };
}

/** A pre-release carries a suffix after the numbers: v2.5.0-rc1. */
export const isPreRelease = (v: string) => /^v?\d[\d.]*-/.test(v);

/** -1, 0, 1 for dotted versions ("2.10.0" > "2.9.3"); a pre-release ranks below its release ("2.5.0-rc1" < "2.5.0"). */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => {
    const [main, ...pre] = v.replace(/^v/, "").split("-");
    return { nums: main.split(".").map((x) => Number(x) || 0), pre: pre.join("-") };
  };
  const pa = split(a), pb = split(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) if ((pa.nums[i] ?? 0) !== (pb.nums[i] ?? 0)) return (pa.nums[i] ?? 0) > (pb.nums[i] ?? 0) ? 1 : -1;
  if (!pa.pre !== !pb.pre) return pa.pre ? -1 : 1;
  return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
}

/** Keys and their fingerprints in an allowed_signers file. */
export async function fingerprints(file: string): Promise<{ who: string; fp: string }[]> {
  if (!existsSync(file)) return [];
  const out: { who: string; fp: string }[] = [];
  for (const l of readFileSync(file, "utf8").split("\n")) {
    const m = /^(\S+)\s+(?:\S*namespaces="[^"]*"\S*\s+)?((?:ssh-|sk-|ecdsa-)\S+\s+\S+)/.exec(l.trim());
    if (!m) continue;
    const p = Bun.spawn(["ssh-keygen", "-lf", "-"], { stdin: new Blob([m[2] + "\n"]), stdout: "pipe", stderr: "ignore" });
    const fp = (await new Response(p.stdout).text()).trim().split(/\s+/)[1];
    if (fp) out.push({ who: m[1], fp });
  }
  return out;
}

const hasSigners = (text: string) => /\S/.test(text.replace(/^#.*$/gm, ""));
const signers = (file: string) => existsSync(file) && hasSigners(readFileSync(file, "utf8"));

async function verify(root: string, tag: string, file: string): Promise<boolean> {
  const r = await git(root, ["verify-tag", tag], ["-c", "gpg.format=ssh", "-c", `gpg.ssh.allowedSignersFile=${file}`]);
  return r.code === 0;
}

export type UpdateResult =
  | { status: "updated"; from: string; to: string; pinned?: { who: string; fp: string }[]; ignored: string[] }
  | { status: "current"; at: string; pinned?: { who: string; fp: string }[]; ignored: string[] }
  | { status: "unsigned-repo" }
  | { status: "refused"; tag: string; why: string };

/**
 * Picks the newest release tag whose signature is good and moves the checkout to it. `current` is the running
 * version. Newer tags that do not verify are returned as `ignored`, so the caller can say so. Nothing is changed when
 * the answer is not "updated" (or "unsigned-repo", which the caller handles).
 */
export async function secureUpdate(root: string, current: string, pin = PIN()): Promise<UpdateResult> {
  const f = await git(root, ["fetch", "--quiet", "--tags", "--force", "origin"]);
  if (f.code !== 0) throw new Error(`git fetch: ${f.err}`);
  const all = (await git(root, ["tag", "-l", "v*", "--sort=-v:refname"])).out.split("\n").filter(Boolean);
  // Pre-releases are for people already running one.
  const tags = all.filter((t) => isPreRelease(current) || !isPreRelease(t));
  const pinned = signers(pin);
  if (!tags.length) return pinned ? { status: "refused", tag: "(none)", why: "the repository has no release tags" } : { status: "unsigned-repo" };
  // Newest first. A tag that does not verify is skipped, not fatal: otherwise anyone who can push a tag could stop
  // every update. Trust on first use: the first tag whose signature matches the signers file it ships gets pinned.
  const ignored: string[] = [];
  let sawSigners = false;
  for (const tag of tags) {
    const older = compareVersions(tag, current) < 0;
    // Everything after this one is older still; with a pinned key there is nothing left to learn.
    if (older && pinned) return { status: "refused", tag, why: `it is older than the version you run (${current}); refusing to go back` };
    let pinnedNow: { who: string; fp: string }[] | undefined;
    if (!pinned) {
      const shipped = await git(root, ["show", `${tag}:trust/allowed_signers`]);
      if (shipped.code !== 0 || !hasSigners(shipped.out)) {
        ignored.push(tag);
        continue;
      }
      sawSigners = true;
      const tmp = `${pin}.candidate`;
      mkdirSync(dirname(pin), { recursive: true, mode: 0o700 });
      writeFileSync(tmp, shipped.out + "\n", { mode: 0o600 });
      let good: boolean;
      try {
        good = await verify(root, tag, tmp);
      } finally {
        rmSync(tmp, { force: true });
      }
      if (!good) {
        ignored.push(tag);
        continue;
      }
      // Nothing is pinned on a refusal.
      if (older) return { status: "refused", tag, why: `it is older than the version you run (${current}); refusing to go back` };
      writeFileSync(pin, shipped.out + "\n", { mode: 0o600 });
      pinnedNow = await fingerprints(pin);
    } else if (!(await verify(root, tag, pin))) {
      ignored.push(tag);
      continue;
    }
    if (older) return { status: "refused", tag, why: `it is older than the version you run (${current}); refusing to go back` };
    const head = (await git(root, ["rev-parse", "HEAD"])).out;
    const target = (await git(root, ["rev-parse", `${tag}^{commit}`])).out;
    if (head === target) return { status: "current", at: tag, pinned: pinnedNow, ignored };
    const co = await git(root, ["checkout", "--quiet", "--detach", tag]);
    if (co.code !== 0) throw new Error(`git checkout ${tag}: ${co.err}`);
    return { status: "updated", from: current, to: tag, pinned: pinnedNow, ignored };
  }
  // No tag verified. A repository whose tags carry no signers file has no signed releases yet.
  if (!pinned && !sawSigners) return { status: "unsigned-repo" };
  return { status: "refused", tag: tags[0], why: pinned ? "the tag is not signed by a release key you trust (unsigned, or signed by another key)" : "the tag is not signed by the key the release itself lists" };
}
