// One policy for WARN, for every gate and for `vswarm agent` alike.
//
//   BLOCK   always refused: no ssh login, no aws/kube/gcloud credential, no command behind gate cmd, no signature.
//   WARN    allowed by default (`vswarm policy warn allow`), refused everywhere with `vswarm policy warn refuse`.
//
// It is kept sealed in ~/.vswarm/sec/policy.json. A protected key can override it for itself
// (`vswarm agent policy <key> --allow-warn | --strict`, back to this one with `--inherit`); keys protected by vswarm
// 2.7 and older keep the setting they were protected with. A policy file whose seal does not match counts as refuse
// (and the check reports it): an edit by hand can only make vswarm stricter, never let WARN through.

import { lang, t, type Lang } from "../i18n";
import { files, readSealed, writeSealed } from "./store";

export type WarnPolicy = "allow" | "refuse";
/** A protected key's own setting: one of the two, or "inherit" (this policy). */
export type KeyPolicy = WarnPolicy | "inherit";

export const DEFAULT_WARN: WarnPolicy = "allow";

export interface PolicyState {
  warn: WarnPolicy;
  /** Written by `vswarm policy` (otherwise the default applies). */
  set: boolean;
  /** Why the file was not trusted (its seal does not match): WARN then refuses. */
  untrusted?: string;
}

interface PolicyFile {
  warn: WarnPolicy;
  at: number;
}

const valid = (w: unknown): w is WarnPolicy => w === "allow" || w === "refuse";

export async function readPolicy(): Promise<PolicyState> {
  const r = await readSealed<PolicyFile>(files.policy());
  if (r.value === undefined && !r.untrusted) return { warn: DEFAULT_WARN, set: false };
  // The key store did not answer: nothing can be checked, so the stricter of what the file says and the default.
  if (r.nokey) return { warn: r.value?.warn === "refuse" ? "refuse" : DEFAULT_WARN, set: valid(r.value?.warn) };
  if (r.untrusted) return { warn: "refuse", set: true, untrusted: r.untrusted };
  return { warn: valid(r.value?.warn) ? r.value!.warn : "refuse", set: true };
}

export const savePolicy = (warn: WarnPolicy) => writeSealed(files.policy(), { warn, at: Date.now() } satisfies PolicyFile);

/** What a key's own setting comes to under the policy. */
export const effective = (key: KeyPolicy | undefined, global: WarnPolicy): WarnPolicy => (key === "allow" || key === "refuse" ? key : global);

/** One line for the end of `vswarm why` and for `vswarm policy`. */
export function policyLine(p: PolicyState, l: Lang = lang()): string {
  const how = t(p.warn === "allow" ? "cli.policy.allowed" : "cli.policy.refused", {}, l);
  const src = p.untrusted ? t("cli.policy.untrusted", { why: p.untrusted }, l) : p.set ? "" : t("cli.policy.default", {}, l);
  return t("cli.policy.line", { how, src, other: p.warn === "allow" ? "refuse" : "allow" }, l);
}
