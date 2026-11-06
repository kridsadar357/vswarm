// Updating vswarm itself, only to releases signed by a key you already trust.
//
// A security tool that pulls whatever is on GitHub is a way into every machine that runs it: whoever takes over the
// repository (or the maintainer's account) ships code to all of them at the next `vswarm update`. So:
//   · releases are git tags signed with the maintainer's SSH key (git tag -s, gpg.format=ssh)
//   · the first install pins the release keys listed in trust/allowed_signers (trust on first use)
//   · every later update verifies the newest tag against the pinned file on this machine, never against the copy in
//     the repository, and refuses an unsigned tag, a tag signed by another key, or a version older than this one
// Changing the release key therefore needs you: vswarm trust shows the pinned fingerprints.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { HOME } from "../home";

export const PIN = () => process.env.VSWARM_TRUST_FILE ?? join(HOME, "trust", "allowed_signers");

async function git(root: string, args: string[], extra: string[] = []): Promise<{ code: number; out: string; err: string }> {
  const p = Bun.spawn(["git", ...extra, "-C", root, ...args], { stdout: "pipe", stderr: "pipe", stdin: "ignore", env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { code, out: out.trim(), err: err.trim() };
}

/** -1, 0, 1 for dotted versions ("2.10.0" > "2.9.3"). */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[.-]/).map((x) => Number(x) || 0);
  const pb = b.replace(/^v/, "").split(/[.-]/).map((x) => Number(x) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0) ? 1 : -1;
  return 0;
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

const signers = (file: string) => existsSync(file) && /\S/.test(readFileSync(file, "utf8").replace(/^#.*$/gm, ""));

async function verify(root: string, tag: string, file: string): Promise<boolean> {
  const r = await git(root, ["verify-tag", tag], ["-c", "gpg.format=ssh", "-c", `gpg.ssh.allowedSignersFile=${file}`]);
  return r.code === 0;
}

export type UpdateResult =
  | { status: "updated"; from: string; to: string; pinned?: { who: string; fp: string }[] }
  | { status: "current"; at: string; pinned?: { who: string; fp: string }[] }
  | { status: "unsigned-repo" }
  | { status: "refused"; tag: string; why: string };

/**
 * Picks the newest release tag and moves the checkout to it, if its signature is good. `current` is the running
 * version. Nothing is changed when the answer is not "updated" (or "unsigned-repo", which the caller handles).
 */
export async function secureUpdate(root: string, current: string, pin = PIN()): Promise<UpdateResult> {
  const f = await git(root, ["fetch", "--quiet", "--tags", "--force", "origin"]);
  if (f.code !== 0) throw new Error(`git fetch: ${f.err}`);
  const tags = (await git(root, ["tag", "-l", "v*", "--sort=-v:refname"])).out.split("\n").filter(Boolean);
  const tag = tags[0];
  const pinned = signers(pin);
  if (!tag) return pinned ? { status: "refused", tag: "(none)", why: "the repository has no release tags" } : { status: "unsigned-repo" };
  let pinnedNow: { who: string; fp: string }[] | undefined;
  if (!pinned) {
    // First signed release this machine sees: the tag must verify against the signers file it carries.
    const shipped = await git(root, ["show", `${tag}:trust/allowed_signers`]);
    if (shipped.code !== 0 || !/\S/.test(shipped.out.replace(/^#.*$/gm, ""))) return { status: "unsigned-repo" };
    const tmp = `${pin}.candidate`;
    mkdirSync(dirname(pin), { recursive: true, mode: 0o700 });
    writeFileSync(tmp, shipped.out + "\n", { mode: 0o600 });
    if (!(await verify(root, tag, tmp))) return { status: "refused", tag, why: "the tag is not signed by the key the release itself lists" };
    writeFileSync(pin, shipped.out + "\n", { mode: 0o600 });
    pinnedNow = await fingerprints(pin);
  } else if (!(await verify(root, tag, pin))) {
    return { status: "refused", tag, why: "the tag is not signed by a release key you trust (unsigned, or signed by another key)" };
  }
  if (compareVersions(tag, current) < 0) return { status: "refused", tag, why: `it is older than the version you run (${current}); refusing to go back` };
  const head = (await git(root, ["rev-parse", "HEAD"])).out;
  const target = (await git(root, ["rev-parse", `${tag}^{commit}`])).out;
  if (head === target) return { status: "current", at: tag, pinned: pinnedNow };
  const co = await git(root, ["checkout", "--quiet", "--detach", tag]);
  if (co.code !== 0) throw new Error(`git checkout ${tag}: ${co.err}`);
  return { status: "updated", from: current, to: tag, pinned: pinnedNow };
}
