// Reports for one incident, written next to its evidence. Nothing is sent anywhere: these are drafts you review
// and send yourself.
//   report.md          for your security / IT team
//   report.json        the same, for tools
//   osv-drafts/*.json  OpenSSF malicious-packages entries for packages you found (OSV format)
//   registries.md      where to report each malicious package, and what to include

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Incident } from "./respond";
import { VERSION } from "../home";

const ECOSYSTEM: Record<string, string> = { npm: "npm", pip: "PyPI", cargo: "crates.io" };

const REPORT_TO: Record<string, string> = {
  npm: "npm: https://www.npmjs.com/support (choose “Report malware”), or the “Report malware” link on the package page",
  PyPI: "PyPI: the “Report project as malware” link on the project page (https://pypi.org/project/<name>/)",
  "crates.io": "crates.io: email help@crates.io and the Rust security team (https://www.rust-lang.org/policies/security)",
  brew: "Homebrew tap: open an issue on the tap's repository, and report the account to GitHub (https://github.com/contact/report-abuse)",
};

export function writeReport(inc: Incident): string[] {
  const out: string[] = [];
  const crit = inc.findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const md = [
    `# Security incident ${inc.id}`,
    ``,
    `| | |`,
    `|---|---|`,
    `| Machine | ${inc.host} (user ${inc.user}) |`,
    `| Opened | ${new Date(inc.at).toISOString()} |`,
    `| Found by | vswarm ${VERSION} |`,
    `| Serious findings | ${crit.length} of ${inc.findings.length} |`,
    ``,
    `## What was found`,
    ``,
    ...inc.findings.flatMap((f) => [
      `### ${f.severity.toUpperCase()} · ${f.title}`,
      ...f.detail.filter(Boolean).map((d) => `- ${d}`),
      ...(f.fix ? [`- Suggested action: ${f.fix}`] : []),
      `- Finding id: \`${f.id}\``,
      ``,
    ]),
    `## Evidence`,
    ``,
    `Copies and snapshots are in \`evidence/\`; \`evidence/MANIFEST.sha256\` lists their SHA-256.`,
    ``,
    `| SHA-256 | Path |`,
    `|---|---|`,
    ...inc.evidence.map((e) => `| \`${e.sha256 ?? "—"}\` | ${e.path}${e.note ? ` (${e.note})` : ""} |`),
    ``,
    `## Actions taken`,
    ``,
    ...inc.actions.map((a) => `- [${a.done ? "x" : " "}] ${new Date(a.at).toISOString()} · ${a.what}${a.detail && a.detail !== "skipped" ? ` — \`${a.detail}\`` : a.detail === "skipped" ? " (skipped)" : ""}`),
    ``,
    `## Credentials to rotate (from a different, clean device)`,
    ``,
    ...inc.credentials.map((cr) => `- [ ] ${cr}`),
    ``,
    `## Next steps`,
    ``,
    `1. Rotate every credential above, starting with production access.`,
    `2. Check production audit logs (cloud trail, Kubernetes audit, VPN, SSO) for use of this machine's credentials since the first suspicious change.`,
    `3. Erase and reinstall this machine if any finding is critical or you cannot explain a high one.`,
    `4. Report malicious packages to their registry and to OpenSSF (see \`registries.md\`).`,
    `5. For an organisation: notify your CSIRT; in Thailand, ThaiCERT (https://www.thaicert.or.th); and your regulator where reporting is required.`,
    `6. When clean: \`vswarm baseline\`, then \`vswarm unlock\`.`,
    ``,
  ].join("\n");
  writeFileSync(join(inc.dir, "report.md"), md, { mode: 0o600 });
  out.push(join(inc.dir, "report.md"));
  writeFileSync(join(inc.dir, "report.json"), JSON.stringify({ ...inc, generator: `vswarm ${VERSION}` }, null, 2), { mode: 0o600 });
  out.push(join(inc.dir, "report.json"));

  // Packages to report: known-malicious ones and look-alikes, plus third-party taps.
  const pkgs = inc.findings.filter((f) => ["malicious", "lookalike", "brew-tap", "install-scripts"].includes(f.rule) && f.item);
  if (pkgs.length) {
    const drafts = join(inc.dir, "osv-drafts");
    mkdirSync(drafts, { recursive: true, mode: 0o700 });
    const lines = [`# Where to report the packages from incident ${inc.id}`, "", "Review each draft before sending. Remove anything that identifies you or your company if you prefer.", ""];
    for (const f of pkgs) {
      const i = f.item!;
      const eco = ECOSYSTEM[i.kind] ?? (i.kind.startsWith("brew") ? "brew" : i.kind);
      lines.push(`## ${i.name}${i.version ? `@${i.version}` : ""} (${eco})`, "", `- Why: ${f.title}`, ...f.detail.filter(Boolean).map((d) => `- ${d}`), `- Report to: ${REPORT_TO[eco] ?? "the publisher and the platform it came from"}`);
      if (ECOSYSTEM[i.kind]) {
        const osv = {
          schema_version: "1.6.0",
          id: `MAL-0000-DRAFT-${i.name.replace(/[^A-Za-z0-9]/g, "-")}`,
          summary: `Malicious code in ${i.name} (${eco})`,
          details: `Found by vswarm on a developer machine. ${f.title}. ${f.detail.join(" ")}`.trim(),
          affected: [{ package: { ecosystem: eco, name: i.name }, versions: i.version ? [i.version] : [] }],
          credits: [{ name: "vswarm user", type: "FINDER" }],
          database_specific: { "malicious-packages-origins": [{ source: "vswarm", import_time: new Date().toISOString() }] },
        };
        const file = join(drafts, `${i.name.replace(/[^A-Za-z0-9@._-]/g, "_")}.json`);
        writeFileSync(file, JSON.stringify(osv, null, 2), { mode: 0o600 });
        lines.push(`- OpenSSF draft: \`osv-drafts/${file.split(/[\\/]/).pop()}\` → pull request to https://github.com/ossf/malicious-packages`);
      }
      lines.push("");
    }
    writeFileSync(join(inc.dir, "registries.md"), lines.join("\n"), { mode: 0o600 });
    out.push(join(inc.dir, "registries.md"));
  }
  return out;
}

// ── The machine's state for a server that decides (vswarm report --json)
//
// A small JSON document a bastion, an SSH CA or a team script can check before it grants access: who, which machine,
// when, the verdict and the findings that led to it. Signed with an SSH key (`ssh-keygen -Y sign`, namespace
// vswarm-report) when asked; the server verifies it against the device keys it knows and refuses a stale one.
// Values of credentials never appear, only finding titles.

export const REPORT_NAMESPACE = "vswarm-report";

export interface Posture {
  schema: "vswarm-report/1";
  host: string;
  user: string;
  at: string;
  vswarm: string;
  verdict: "pass" | "warn" | "block";
  locked?: { incident: string; reason: string };
  baselineAt?: string;
  findings: { id: string; rule: string; severity: string; title: string }[];
  notes: string[];
  team?: { name: string; serial: number };
}

export function posture(r: import("./engine").Check, team?: { name: string; serial: number }): Posture {
  return {
    schema: "vswarm-report/1",
    host: r.scan.host,
    user: r.scan.user,
    at: new Date().toISOString(),
    vswarm: VERSION,
    verdict: r.verdict,
    ...(r.lock ? { locked: { incident: r.lock.incident, reason: r.lock.reason } } : {}),
    ...(r.baseline ? { baselineAt: new Date(r.baseline.at).toISOString() } : {}),
    findings: r.findings.filter((f) => f.severity !== "info").map((f) => ({ id: f.id, rule: f.rule, severity: f.severity, title: f.title })),
    notes: r.notes,
    ...(team ? { team } : {}),
  };
}

/** An SSH signature over the exact bytes (the key may be a file, or a public key whose private half is in ssh-agent). */
export async function signReport(text: string, key: string): Promise<string> {
  const p = Bun.spawn(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", REPORT_NAMESPACE], { stdin: new Blob([text]), stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  if (code !== 0 || !out.includes("BEGIN SSH SIGNATURE")) throw new Error(`could not sign the report with ${key}: ${err.trim().split("\n")[0] || `ssh-keygen exit ${code}`}`);
  return out;
}

/** Writes report.json (and .sig) into a folder a team collects, named by host and time so reports never overwrite each other. */
export function writePosture(dir: string, text: string, sig?: string): string[] {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = JSON.parse(text) as Posture;
  const name = `vswarm-report-${p.host.replace(/[^A-Za-z0-9._-]/g, "_")}-${p.at.replace(/[:.]/g, "-")}.json`;
  writeFileSync(join(dir, name), text, { mode: 0o600 });
  const out = [join(dir, name)];
  if (sig) {
    writeFileSync(join(dir, `${name}.sig`), sig, { mode: 0o600 });
    out.push(join(dir, `${name}.sig`));
  }
  return out;
}
