// aws and kubectl credential gates (awsgate.ts, kubegate.ts). Every test works in temp folders: no real ~/.aws,
// kubeconfig or vswarm state is read or written, and no real aws or kubectl runs.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { awsGateText, awsPlan, awsStatus, awsUngateText, awsWord, gateAws } from "../src/sec/awsgate";
import { gatedExec, gateKube, kubeContexts, kubeGateText, kubeLocate, kubeStatus, kubeUngateText, kubeUserOf, scalar, yamlLines, yamlWord } from "../src/sec/kubegate";
import { cloudDoctor, cloudUninstall, loadCloudGates, type CloudEnv } from "../src/sec/cloudgate";
import { behindGate, toolHelpers } from "../src/sec/collect/tools";
import { evaluate } from "../src/sec/rules";
import { saveLast } from "../src/sec/store";
import type { Ctx } from "../src/sec/ctx";
import type { Scan, Verdict } from "../src/sec/types";

const WIN = process.platform === "win32";
const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-cred-${tag}-`));
const CLI = join(import.meta.dir, "../src/cli.ts");
const V = ["/v/vswarm"];

async function withSec<T>(fn: (sec: string) => Promise<T> | T): Promise<T> {
  const prev = process.env.VSWARM_SEC_DIR;
  const sec = tmp("sec");
  process.env.VSWARM_SEC_DIR = sec;
  try {
    return await fn(sec);
  } finally {
    if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prev;
  }
}

async function quiet(fn: () => Promise<unknown>): Promise<string> {
  const orig = console.log;
  let out = "";
  console.log = (...a: unknown[]) => void (out += a.join(" ") + "\n");
  try {
    await fn();
  } finally {
    console.log = orig;
  }
  return out;
}

const AWS_CONFIG = [
  "# my aws config",
  "[default]",
  "region = eu-west-1",
  "",
  "[sso-session corp]",
  "sso_start_url = https://corp.awsapps.com/start",
  "sso_region = eu-west-1",
  "sso_registration_scopes = sso:account:access",
  "",
  "[profile prod-sso]  ; the production account",
  "sso_session = corp",
  "sso_account_id = 111111111111",
  "# the admin role",
  "sso_role_name = Admin",
  "region = eu-west-1",
  "output = json",
  "",
  "[profile prod-admin]",
  "role_arn = arn:aws:iam::111111111111:role/Break-glass",
  "source_profile = prod-sso",
  "",
  "[profile dev-proc]",
  "credential_process = /opt/idp/aws-creds --account dev",
  "s3 =",
  "  max_concurrent_requests = 10",
  "",
  "[profile static]",
  "region = us-east-1",
  "",
  "[profile ec2]",
  "role_arn = arn:aws:iam::1:role/x",
  "credential_source = Ec2InstanceMetadata",
  "",
  "[profile loop-a]",
  "role_arn = arn:aws:iam::1:role/a",
  "source_profile = loop-b",
  "[profile loop-b]",
  "role_arn = arn:aws:iam::1:role/b",
  "source_profile = loop-a",
  "",
  "[profile bare]",
  "region = eu-west-1",
].join("\n") + "\n";
const AWS_CREDS = "[static]\naws_access_key_id = AKIAEXAMPLEEXAMPLE12\naws_secret_access_key = x\n";

describe("aws: which profile, and why not", () => {
  test("SSO, credential_process and a role's source are gated; static keys, machine roles, loops and nothing are refused", () => {
    expect(awsPlan("prod-sso", AWS_CONFIG, AWS_CREDS)).toEqual({ profile: "prod-sso", kind: "sso", chain: [] });
    expect(awsPlan("dev-proc", AWS_CONFIG, AWS_CREDS).kind).toBe("process");
    expect(awsPlan("prod-admin", AWS_CONFIG, AWS_CREDS)).toEqual({ profile: "prod-sso", kind: "sso", chain: ["prod-admin"] });
    expect(() => awsPlan("static", AWS_CONFIG, AWS_CREDS)).toThrow("static access keys (in ~/.aws/credentials)");
    expect(() => awsPlan("static", AWS_CONFIG, AWS_CREDS)).toThrow("IAM Identity Center");
    expect(() => awsPlan("ec2", AWS_CONFIG, AWS_CREDS)).toThrow("Ec2InstanceMetadata");
    expect(() => awsPlan("loop-a", AWS_CONFIG, AWS_CREDS)).toThrow("source_profile loop (loop-a → loop-b → loop-a)");
    expect(() => awsPlan("bare", AWS_CONFIG, AWS_CREDS)).toThrow("no credential source");
    expect(() => awsPlan("nope", AWS_CONFIG, AWS_CREDS)).toThrow("no profile nope");
    expect(() => awsPlan("vswarm-src-prod-sso", AWS_CONFIG, AWS_CREDS)).toThrow("gate the profile itself");
    // A role whose source holds static keys: refused at the source, and said through which role.
    const chain = AWS_CONFIG + "[profile via-static]\nrole_arn = arn:aws:iam::1:role/y\nsource_profile = static\n";
    expect(() => awsPlan("via-static", chain, AWS_CREDS)).toThrow("static (the source of via-static) uses static access keys");
    // Keys pasted into the config count as static too, and SSO next to credential_process is ambiguous.
    expect(() => awsPlan("k", "[profile k]\naws_access_key_id = AKIA\n", "")).toThrow("in ~/.aws/config");
    expect(() => awsPlan("both", "[profile both]\nsso_session = corp\ncredential_process = /x\n", "")).toThrow("both SSO settings and a credential_process");
    // [default] works under either spelling, from either file.
    expect(() => awsPlan("default", "[profile default]\ncredential_process = /x\n", "")).not.toThrow();
  });

  test("SSO: the settings move to vswarm-src-<name>, credential_process asks it, and --off puts the bytes back", () => {
    const { text, hook } = awsGateText(AWS_CONFIG, awsPlan("prod-sso", AWS_CONFIG, ""), V, false);
    expect(text).toContain([
      "[profile prod-sso]  ; the production account",
      "# vswarm gate aws: the SSO settings are in [profile vswarm-src-prod-sso] now; vswarm gate aws --off prod-sso puts them back",
      "credential_process = /v/vswarm preflight --quiet --then aws configure export-credentials --profile vswarm-src-prod-sso --format process",
      "# the admin role",
      "region = eu-west-1",
      "output = json",
      "",
      "[profile vswarm-src-prod-sso]",
      "# written by vswarm gate aws: the SSO sign-in of [profile prod-sso]; sign in with aws sso login --profile vswarm-src-prod-sso",
      "sso_session = corp",
      "sso_account_id = 111111111111",
      "sso_role_name = Admin",
      "",
      "[profile prod-admin]",
    ].join("\n"));
    // Nothing else moved; the companion has no credential_process, so it cannot ask itself.
    expect(text.replace(/\[profile prod-sso\][\s\S]*?(?=\[profile prod-admin\])/, "")).toBe(AWS_CONFIG.replace(/\[profile prod-sso\][\s\S]*?(?=\[profile prod-admin\])/, ""));
    expect(hook.companion).not.toContain("credential_process");
    // Asked again, it is already gated: no second wrapper.
    expect(awsPlan("prod-sso", text, "").kind).toBe("gated");
    expect(awsPlan("prod-admin", text, "")).toEqual({ profile: "prod-sso", kind: "gated", chain: ["prod-admin"] });
    expect(() => awsGateText(text, awsPlan("prod-sso", text, ""), V, false)).toThrow("already runs vswarm preflight");
    const h = { file: "f", backup: "b", for: ["prod-sso"], at: 0, ...hook };
    expect(awsUngateText(text, "prod-sso", h)).toEqual({ text: AWS_CONFIG, notes: [] });
  });

  test("credential_process: wrapped where it stands; CRLF, a last profile without a newline, and comments survive", () => {
    const crlf = AWS_CONFIG.replace(/\n/g, "\r\n");
    const { text, hook } = awsGateText(crlf, awsPlan("dev-proc", crlf, ""), ["/Users/a b/.vswarm/bin/vswarm"], false);
    expect(text).toContain("[profile dev-proc]\r\ncredential_process = '/Users/a b/.vswarm/bin/vswarm' preflight --quiet --then /opt/idp/aws-creds --account dev\r\ns3 =\r\n");
    expect(text.split("\r\n").length).toBe(crlf.split("\r\n").length);
    expect(awsUngateText(text, "dev-proc", { file: "f", backup: "b", for: [], at: 0, ...hook }).text).toBe(crlf);
    // The last section of a file with no final newline; an SSO profile last of all gets its companion after it.
    const last = "[profile a]\nsso_start_url = https://x.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 1\nsso_role_name = R";
    const g = awsGateText(last, awsPlan("a", last, ""), V, false);
    expect(g.text.endsWith("[profile vswarm-src-a]\n# written by vswarm gate aws: the SSO sign-in of [profile a]; sign in with aws sso login --profile vswarm-src-a\nsso_start_url = https://x.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 1\nsso_role_name = R\n")).toBe(true);
    expect(awsUngateText(g.text, "a", { file: "f", backup: "b", for: [], at: 0, ...g.hook }).text).toBe(last);
  });

  test("edited by hand after gating: --off swaps back only vswarm's lines and keeps the edit; a removed gate is left alone", () => {
    const { text, hook } = awsGateText(AWS_CONFIG, awsPlan("prod-sso", AWS_CONFIG, ""), V, false);
    const h = { file: "f", backup: "b", for: [], at: 0, ...hook };
    const edited = text.replace("output = json\n", "output = json\ncli_pager =\n");
    const r = awsUngateText(edited, "prod-sso", h);
    expect(r.text).toBe(AWS_CONFIG.replace("output = json\n", "output = json\ncli_pager =\n"));
    expect(r.notes[0]).toContain("your other changes kept");
    const gone = text.replace(/credential_process = .*\n/, "credential_process = /my/own\n");
    const r2 = awsUngateText(gone, "prod-sso", h);
    expect(r2.notes.join(" ")).toContain("no longer has the lines vswarm wrote");
    // The SSO settings stay in the companion: removing it would lose them.
    expect(r2.text).toBe(gone);
    expect(r2.notes.join(" ")).toContain("keeps the SSO settings");
  });

  test("the launcher's words, for botocore's split: POSIX quoting, and double quotes on Windows", () => {
    expect(awsWord("/Users/a/.vswarm/bin/vswarm", false)).toBe("/Users/a/.vswarm/bin/vswarm");
    expect(awsWord("/Users/o'x/bun", false)).toBe(`'/Users/o'"'"'x/bun'`);
    expect(awsWord("C:\\Users\\a\\bun.exe", false)).toBe(`'C:\\Users\\a\\bun.exe'`);
    expect(awsWord("C:\\Users\\a\\bun.exe", true)).toBe("C:\\Users\\a\\bun.exe");
    expect(awsWord("C:\\Program Files\\bun\\bun.exe", true)).toBe('"C:\\Program Files\\bun\\bun.exe"');
    expect(() => awsWord('C:\\a"b', true)).toThrow("double quote");
    const g = awsGateText(AWS_CONFIG, awsPlan("dev-proc", AWS_CONFIG, ""), ["C:\\Program Files\\bun.exe", "C:\\v\\src\\cli.ts"], true);
    expect(g.text).toContain('credential_process = "C:\\Program Files\\bun.exe" C:\\v\\src\\cli.ts preflight --quiet --then /opt/idp/aws-creds --account dev\n');
    // Gated with a Windows launcher, it is still recognised as gated.
    expect(awsPlan("dev-proc", g.text, "").kind).toBe("gated");
  });

  test.skipIf(WIN || !Bun.which("python3"))("botocore's shlex.split reads credential_process as vswarm, preflight, then the original", async () => {
    const { text } = awsGateText(AWS_CONFIG, awsPlan("prod-sso", AWS_CONFIG, ""), ["/Users/o'x/b b/bun", "/v/cli.ts"], false);
    const cp = /^credential_process = (.*)$/m.exec(text)![1];
    const p = Bun.spawn(["python3", "-I", "-c", "import json,shlex,sys; print(json.dumps(shlex.split(sys.argv[1])))", cp], { stdout: "pipe" });
    expect(JSON.parse(await new Response(p.stdout).text())).toEqual(["/Users/o'x/b b/bun", "/v/cli.ts", "preflight", "--quiet", "--then", "aws", "configure", "export-credentials", "--profile", "vswarm-src-prod-sso", "--format", "process"]);
  });

  test("gate aws: on, refusals, again, status, a hand edit, off byte for byte, doctor and uninstall, in a temp AWS_CONFIG_FILE", () => withSec(async () => {
    const dir = tmp("aws");
    const config = join(dir, "config"), creds = join(dir, "credentials");
    writeFileSync(config, AWS_CONFIG);
    writeFileSync(creds, AWS_CREDS);
    const e: CloudEnv = { env: { AWS_CONFIG_FILE: config, AWS_SHARED_CREDENTIALS_FILE: creds }, home: "/nonexistent", launcher: V };
    let done = true;
    const said = await quiet(async () => void (done = await gateAws(["prod-admin", "dev-proc", "static", "ec2"], e)));
    expect(done).toBe(false);
    expect(said).toContain("aws profile prod-admin: credentials come only after vswarm preflight passes (prod-admin → prod-sso");
    expect(said).toContain("aws sso login --sso-session corp");
    expect(said).toContain("aws profile static not gated");
    expect(said).toContain("aws profile ec2 not gated");
    const gated = readFileSync(config, "utf8");
    expect(gated.match(/preflight --quiet --then/g)!.length).toBe(2);
    expect(Object.keys(loadCloudGates().aws).sort()).toEqual(["dev-proc", "prod-sso"]);
    expect(loadCloudGates().aws["prod-sso"].for).toEqual(["prod-admin"]);
    // One backup, of the file as it was.
    expect(readFileSync(loadCloudGates().aws["dev-proc"].backup, "utf8")).toBe(AWS_CONFIG);
    // Again: no second wrapper; the profile itself joins the list it covers.
    expect(await quiet(() => gateAws(["prod-sso", "dev-proc"], e))).toContain("already gated");
    expect(readFileSync(config, "utf8")).toBe(gated);
    expect(loadCloudGates().aws["prod-sso"].for).toEqual(["prod-admin", "prod-sso"]);
    expect(awsStatus(e).map((s) => [s.name, s.ok])).toEqual([["prod-sso", true], ["dev-proc", true]]);
    expect((await cloudDoctor(e)).filter((d) => d.text.startsWith("aws gate")).map((d) => d.level)).toEqual(["ok", "ok"]);
    // Someone puts the old command back by hand: status says so.
    writeFileSync(config, gated.replace(/credential_process = \/v\/vswarm preflight --quiet --then (\/opt\/idp)/, "credential_process = $1"));
    expect(awsStatus(e).find((s) => s.name === "dev-proc")).toMatchObject({ ok: false });
    expect(await quiet(() => gateAws(["status"], e))).toContain("changed by hand");
    // Static keys added later for a gated profile bypass the gate: said too.
    writeFileSync(config, gated);
    writeFileSync(creds, AWS_CREDS + "[dev-proc]\naws_access_key_id = AKIAEXAMPLEEXAMPLE34\n");
    expect(awsStatus(e).find((s) => s.name === "dev-proc")!.detail).toContain("the gate is bypassed");
    writeFileSync(creds, AWS_CREDS);
    // Off through the role's name restores its source; then the rest; the file is the same bytes as before.
    expect(await quiet(() => gateAws(["--off", "prod-admin"], e))).toContain("aws profile prod-sso restored");
    expect(await quiet(() => gateAws(["--off"], e))).toContain("aws profile dev-proc restored");
    expect(readFileSync(config, "utf8")).toBe(AWS_CONFIG);
    expect(loadCloudGates().aws).toEqual({});
    // Uninstall turns every aws gate off.
    await quiet(() => gateAws(["dev-proc"], e));
    expect((await cloudUninstall({ files: [], body: () => "" })).join("\n")).toContain("aws profile dev-proc restored");
    expect(readFileSync(config, "utf8")).toBe(AWS_CONFIG);
  }));
});

const KUBECONFIG = [
  "apiVersion: v1",
  "clusters:",
  "- cluster:",
  "    server: https://prod.example:6443",
  "  name: prod",
  "contexts:",
  "- context:",
  "    cluster: prod",
  "    user: prod-eks",
  "  name: prod",
  "- context:",
  "    cluster: prod",
  "    user: prod-eks",
  "  name: prod-ro",
  "- context:",
  "    cluster: prod",
  "    user: ci",
  "  name: ci",
  "- context:",
  "    cluster: prod",
  "    user: admin",
  "  name: admin",
  "- name: oidc",
  "  context:",
  "    cluster: prod",
  "    user: oidc",
  "- context:",
  "    cluster: prod",
  "    user: legacy",
  "  name: legacy",
  "current-context: prod",
  "kind: Config",
  "preferences: {}",
  "users:",
  "- name: prod-eks",
  "  user:",
  "    exec:",
  "      apiVersion: client.authentication.k8s.io/v1beta1",
  "      args:",
  "      - --region",
  "      - eu-west-1",
  "      - eks",
  "      - get-token",
  "      - --cluster-name",
  "      - 'prod'   # the cluster",
  "      command: aws",
  "      env:",
  "      - name: AWS_PROFILE",
  "        value: prod-sso",
  "      interactiveMode: IfAvailable",
  "      provideClusterInfo: false",
  "- name: ci",
  "  user:",
  "    token: abc.def.ghi",
  "- name: admin",
  "  user:",
  "    client-certificate-data: Zm9v",
  "    client-key-data: Zm9v",
  "- name: oidc",
  "  user:",
  "    exec:",
  '      command: "kubectl"',
  '      args: [oidc-login, get-token, "--oidc-issuer-url=https://idp.example"]',
  "      apiVersion: client.authentication.k8s.io/v1beta1",
  "- name: legacy",
  "  user:",
  "    auth-provider:",
  "      name: oidc",
].join("\n") + "\n";

describe("kubectl: which user, and why not", () => {
  test("the reader: contexts in either key order, users and their exec plugins, quoted and flow values", () => {
    const ls = yamlLines(KUBECONFIG);
    expect([...kubeContexts(ls)]).toEqual([["prod", "prod-eks"], ["prod-ro", "prod-eks"], ["ci", "ci"], ["admin", "admin"], ["oidc", "oidc"], ["legacy", "legacy"]]);
    const eks = kubeUserOf(ls, "prod-eks")!;
    expect(eks.how).toBe("exec");
    expect([eks.exec!.command, ...eks.exec!.args]).toEqual(["aws", "--region", "eu-west-1", "eks", "get-token", "--cluster-name", "prod"]);
    expect(kubeUserOf(ls, "oidc")!.exec!.args).toEqual(["oidc-login", "get-token", "--oidc-issuer-url=https://idp.example"]);
    expect(["ci", "admin", "legacy"].map((u) => kubeUserOf(ls, u)!.how)).toEqual(["token", "client certificate", "auth-provider"]);
    expect(scalar(`"a\\"b" # c`)).toBe('a"b');
    expect(scalar(`'it''s'`)).toBe("it's");
    expect(() => scalar("|")).toThrow("block style");
    expect(yamlWord("preflight")).toBe("preflight");
    expect(yamlWord("--quiet")).toBe("--quiet");
    expect(yamlWord("true")).toBe("'true'");
    expect(yamlWord("it's")).toBe("'it''s'");
    expect(yamlWord("a\nb")).toBe('"a\\nb"');
    expect(yamlWord("C:\\Program Files\\bun.exe")).toBe("'C:\\Program Files\\bun.exe'");
  });

  test("the exec block is rewritten in place: env and the rest kept, the plugin after preflight, off is the same bytes", () => {
    const { text, hook } = kubeGateText(KUBECONFIG, "prod-eks", ["/Users/a b/.vswarm/bin/vswarm"]);
    expect(text).toContain([
      "- name: prod-eks",
      "  user:",
      "    exec:",
      "      apiVersion: client.authentication.k8s.io/v1beta1",
      "      command: '/Users/a b/.vswarm/bin/vswarm'",
      "      args:",
      "      - preflight",
      "      - --quiet",
      "      - --then",
      "      - aws",
      "      - --region",
      "      - eu-west-1",
      "      - eks",
      "      - get-token",
      "      - --cluster-name",
      "      - prod",
      "      env:",
      "      - name: AWS_PROFILE",
      "        value: prod-sso",
      "      interactiveMode: IfAvailable",
      "      provideClusterInfo: false",
      "- name: ci",
    ].join("\n"));
    // Only that block changed.
    const outside = (t: string) => t.replace(/- name: prod-eks[\s\S]*?(?=- name: ci\n)/, "");
    expect(outside(text)).toBe(outside(KUBECONFIG));
    const ex = kubeUserOf(yamlLines(text), "prod-eks")!.exec!;
    expect(gatedExec(ex.command, ex.args)).toBe(true);
    expect(() => kubeGateText(text, "prod-eks", V)).toThrow("already runs vswarm preflight");
    expect(kubeUngateText(text, "prod-eks", { file: "f", backup: "b", for: [], at: 0, ...hook })).toEqual({ text: KUBECONFIG });
    // A flow list of args, and CRLF line endings, round-trip too.
    const crlf = KUBECONFIG.replace(/\n/g, "\r\n");
    const g = kubeGateText(crlf, "oidc", ["C:\\Users\\me\\.bun\\bin\\bun.exe", "C:\\vswarm\\src\\cli.ts"]);
    expect(g.text).toContain("\r\n      command: 'C:\\Users\\me\\.bun\\bin\\bun.exe'\r\n      args:\r\n      - 'C:\\vswarm\\src\\cli.ts'\r\n      - preflight\r\n");
    const back = kubeUserOf(yamlLines(g.text), "oidc")!.exec!;
    expect([back.command, ...back.args]).toEqual(["C:\\Users\\me\\.bun\\bin\\bun.exe", "C:\\vswarm\\src\\cli.ts", "preflight", "--quiet", "--then", "kubectl", "oidc-login", "get-token", "--oidc-issuer-url=https://idp.example"]);
    expect(kubeUngateText(g.text, "oidc", { file: "f", backup: "b", for: [], at: 0, ...g.hook }).text).toBe(crlf);
  });

  test("static tokens, client certificates, passwords, auth-providers and files not in block style are refused", () => {
    expect(() => kubeGateText(KUBECONFIG, "ci", V)).toThrow("static token");
    expect(() => kubeGateText(KUBECONFIG, "ci", V)).toThrow("kubelogin for OIDC");
    expect(() => kubeGateText(KUBECONFIG, "admin", V)).toThrow("client certificate");
    expect(() => kubeGateText(KUBECONFIG, "legacy", V)).toThrow("auth-provider");
    expect(() => kubeGateText("users:\n- name: p\n  user:\n    username: a\n    password: b\n", "p", V)).toThrow("username and password");
    expect(() => kubeGateText("users:\n- name: m\n  user:\n    token: t\n    exec:\n      command: aws\n", "m", V)).toThrow("remove the stored one first");
    expect(() => kubeGateText('{"apiVersion":"v1","users":[{"name":"j","user":{"exec":{"command":"aws"}}}]}', "j", V)).toThrow("no user j");
    expect(() => kubeGateText("users: [{name: f, user: {exec: {command: aws}}}]\n", "f", V)).toThrow("flow style");
    expect(() => kubeGateText("users:\n- name: f\n  user: {exec: {command: aws}}\n", "f", V)).toThrow("block style");
    expect(() => kubeGateText("users:\n- name: f\n  user:\n    exec:\n      command: aws\n        --profile x\n", "f", V)).toThrow("several lines");
  });

  test("rewritten by kubectl after gating: off puts the command and args back in the new layout; a removed gate is left alone", () => {
    const { text, hook } = kubeGateText(KUBECONFIG, "prod-eks", V);
    const h = { file: "f", backup: "b", for: ["prod"], at: 0, ...hook };
    // kubectl writes keys sorted and plain where it can.
    const rewritten = text.replace("      command: /v/vswarm\n      args:\n", "      args:\n").replace("      env:\n", "      command: /v/vswarm\n      env:\n").replace("    exec:\n", "    exec:\n");
    const r = kubeUngateText(rewritten, "prod-eks", h);
    expect(r.note).toContain("rewritten since vswarm changed it");
    const ex = kubeUserOf(yamlLines(r.text), "prod-eks")!.exec!;
    expect([ex.command, ...ex.args]).toEqual(["aws", "--region", "eu-west-1", "eks", "get-token", "--cluster-name", "prod"]);
    expect(r.text).toContain("      - name: AWS_PROFILE\n        value: prod-sso\n");
    const own = text.replace("command: /v/vswarm", "command: aws-iam-authenticator").replace("      - preflight\n      - --quiet\n      - --then\n", "");
    expect(kubeUngateText(own, "prod-eks", h)).toEqual({ text: own, note: "the exec plugin of user prod-eks no longer runs vswarm preflight; left as it is" });
  });

  test("KUBECONFIG with several files: the context from the first that has it, the user written where it is defined", () => {
    const dir = tmp("kube");
    const a = join(dir, "a.yaml"), b = join(dir, "b.yaml");
    writeFileSync(a, "apiVersion: v1\ncontexts:\n- context:\n    user: shared\n  name: prod\n");
    writeFileSync(b, "apiVersion: v1\ncontexts:\n- context:\n    user: other\n  name: prod\nusers:\n- name: shared\n  user:\n    exec:\n      command: kubelogin\n      args: [get-token]\n");
    expect(kubeLocate("prod", [a, b])).toEqual({ user: "shared", file: b });
    expect(kubeLocate("prod", [join(dir, "missing"), a, b]).file).toBe(b);
    expect(() => kubeLocate("dev", [a, b])).toThrow("no context dev");
    expect(() => kubeLocate("prod", [a])).toThrow("which no kubeconfig defines");
  });

  test("gate kube: on, refusals, again, status, a hand edit, off byte for byte, doctor and uninstall, with KUBECONFIG", () => withSec(async () => {
    const dir = tmp("kube");
    const main = join(dir, "config"), extra = join(dir, "extra");
    writeFileSync(main, KUBECONFIG);
    const extraText = "apiVersion: v1\ncontexts:\n- context:\n    user: gke\n  name: gke\nusers:\n- name: gke\n  user:\n    exec:\n      command: gke-gcloud-auth-plugin\n      apiVersion: client.authentication.k8s.io/v1beta1\n";
    writeFileSync(extra, extraText);
    const e: CloudEnv = { env: { KUBECONFIG: [main, extra].join(delimiter) }, home: "/nonexistent", launcher: V };
    let done = true;
    const said = await quiet(async () => void (done = await gateKube(["prod", "ci", "gke", "nope"], e)));
    expect(done).toBe(false);
    expect(said).toContain("kubectl context prod: user prod-eks gets a token only after vswarm preflight passes");
    expect(said).toContain("kubectl context ci not gated");
    expect(said).toContain("no context nope");
    expect(readFileSync(extra, "utf8")).toContain("      command: /v/vswarm\n      args:\n      - preflight\n      - --quiet\n      - --then\n      - gke-gcloud-auth-plugin\n      apiVersion:");
    const gated = readFileSync(main, "utf8");
    // A second context with the same user: already gated, recorded.
    expect(await quiet(() => gateKube(["prod-ro", "prod"], e))).toContain("already gated (user prod-eks)");
    expect(readFileSync(main, "utf8")).toBe(gated);
    expect(loadCloudGates().kube["prod-eks"].for).toEqual(["prod", "prod-ro"]);
    expect(kubeStatus().map((s) => [s.name, s.ok])).toEqual([["prod-eks", true], ["gke", true]]);
    expect((await cloudDoctor(e)).filter((d) => d.text.startsWith("kubectl gate")).map((d) => d.level)).toEqual(["ok", "ok"]);
    writeFileSync(extra, extraText);
    expect(kubeStatus().find((s) => s.name === "gke")).toMatchObject({ ok: false });
    expect(await quiet(() => gateKube(["--off", "gke"], e))).toContain("no longer runs vswarm preflight; left as it is");
    expect(readFileSync(extra, "utf8")).toBe(extraText);
    // Off by one context of a shared user says the other is ungated too; the file is the same bytes.
    expect(await quiet(() => gateKube(["--off", "prod-ro"], e))).toContain("context prod uses the same user");
    expect(readFileSync(main, "utf8")).toBe(KUBECONFIG);
    expect(existsSync(`${main}`)).toBe(true);
    await quiet(() => gateKube(["prod"], e));
    expect((await cloudUninstall({ files: [], body: () => "" })).join("\n")).toContain("kubectl user prod-eks restored");
    expect(readFileSync(main, "utf8")).toBe(KUBECONFIG);
    expect(loadCloudGates().kube).toEqual({});
  }));
});

describe("vswarm gate aws / gate kube dispatch", () => {
  test("gate aws and gate kube reach their gates; a refusal sets exit code 1 (files only through AWS_CONFIG_FILE and KUBECONFIG)", () => withSec(async () => {
    const dir = tmp("dispatch");
    const keep = { a: process.env.AWS_CONFIG_FILE, c: process.env.AWS_SHARED_CREDENTIALS_FILE, k: process.env.KUBECONFIG, code: process.exitCode };
    const config = join(dir, "config"), kube = join(dir, "kubeconfig");
    writeFileSync(config, AWS_CONFIG);
    writeFileSync(kube, KUBECONFIG);
    process.env.AWS_CONFIG_FILE = config;
    process.env.AWS_SHARED_CREDENTIALS_FILE = join(dir, "credentials");
    process.env.KUBECONFIG = kube;
    try {
      const { gate } = await import("../src/setup");
      process.exitCode = 0;
      expect(await quiet(() => gate(["aws", "dev-proc"], dir))).toContain("aws profile dev-proc: credentials come only after vswarm preflight passes");
      expect(process.exitCode).toBe(0);
      expect(await quiet(() => gate(["kubectl", "ci"], dir))).toContain("static token");
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
      await quiet(() => gate(["kube", "prod"], dir));
      const st = await quiet(() => gate(["status"], dir));
      expect(st).toContain("aws profiles gated: dev-proc");
      expect(st).toContain("kubectl contexts gated: prod");
      await quiet(() => gate(["aws", "--off"], dir));
      await quiet(() => gate(["kube", "--off"], dir));
      expect([readFileSync(config, "utf8"), readFileSync(kube, "utf8")]).toEqual([AWS_CONFIG, KUBECONFIG]);
    } finally {
      for (const [k, v] of [["AWS_CONFIG_FILE", keep.a], ["AWS_SHARED_CREDENTIALS_FILE", keep.c], ["KUBECONFIG", keep.k]] as const)
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      process.exitCode = keep.code;
    }
  }));
});

/** A last check as vswarm writes it, sealed with the key in that temp state folder (the CLI there reads the same key). */
const sealedLast = (sec: string, verdict: string) => {
  const prev = process.env.VSWARM_SEC_DIR;
  process.env.VSWARM_SEC_DIR = sec;
  return saveLast({ verdict: verdict as Verdict, findings: [{ id: "x", rule: "x", severity: "medium", title: "a warning", detail: [] }], at: Date.now(), scan: {} as Scan }).finally(() => {
    if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prev;
  });
};

describe("preflight --then hands the credential through as clean JSON", () => {
  // A stand-in credential command: prints what aws (credential_process) or kubectl (ExecCredential) parses.
  const fake = (json: object) => [process.execPath, "-e", `process.stdout.write(JSON.stringify(${JSON.stringify(json)}) + "\\n")`];
  const run = async (sec: string, argv: string[]) => {
    const p = Bun.spawn(argv, { env: { ...process.env, NO_COLOR: "1", VSWARM_SEC_DIR: sec }, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    return { out, err, code };
  };

  test("aws: the gated credential_process, run on PASS and WARN, prints only the credential on stdout", async () => {
    const sec = tmp("sec");
    const cred = { Version: 1, AccessKeyId: "ASIAFAKEFAKEFAKE", SecretAccessKey: "x", SessionToken: "y", Expiration: "2030-01-01T00:00:00Z" };
    // What credential_process holds after vswarm gate aws, as argv (botocore splits it into these words).
    const argv = [process.execPath, CLI, "preflight", "--quiet", "--then", ...fake(cred)];
    for (const v of ["pass", "warn"]) {
      await sealedLast(sec, v);
      const r = await run(sec, argv);
      expect(r.code).toBe(0);
      expect(JSON.parse(r.out)).toEqual(cred);
      if (v === "warn") expect(r.err).toContain("WARN");
    }
    await sealedLast(sec, "block");
    const b = await run(sec, argv);
    expect(b.code).toBe(3);
    expect(b.out).toBe("");
  }, 60_000);

  test("kubectl: the exec plugin vswarm wrote, read back from the kubeconfig and run, prints the ExecCredential only", async () => {
    const sec = tmp("sec");
    const cred = { apiVersion: "client.authentication.k8s.io/v1beta1", kind: "ExecCredential", status: { token: "t0k3n", expirationTimestamp: "2030-01-01T00:00:00Z" } };
    const [cmd, ...args] = fake(cred);
    const yaml = `users:\n- name: u\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: ${JSON.stringify(cmd)}\n      args: ${JSON.stringify(args)}\n`;
    const { text } = kubeGateText(yaml, "u", [process.execPath, CLI]);
    const x = kubeUserOf(yamlLines(text), "u")!.exec!;
    for (const v of ["pass", "warn"]) {
      await sealedLast(sec, v);
      const r = await run(sec, [x.command!, ...x.args]);
      expect(r.code).toBe(0);
      expect(JSON.parse(r.out)).toEqual(cred);
    }
  }, 60_000);
});

describe("scans: a command behind vswarm's own gate is the command", () => {
  test("only this vswarm's launcher counts; gating is not a change, a look-alike wrapper is", async () => {
    expect(behindGate("/x/vswarm preflight --quiet --then aws eks get-token", [["/x/vswarm"]])).toBe("aws eks get-token");
    expect(behindGate("'/a b/vswarm' preflight --quiet --then /opt/x", [["/a b/vswarm"]])).toBe("/opt/x");
    expect(behindGate('"C:\\Program Files\\bun.exe" C:\\v\\cli.ts preflight --quiet --then x', [["C:\\Program Files\\bun.exe", "C:\\v\\cli.ts"]])).toBe("x");
    expect(behindGate("/tmp/evil/vswarm preflight --quiet --then aws", [["/x/vswarm"]])).toBeUndefined();
    expect(behindGate("/x/vswarm preflight --quiet --then ", [["/x/vswarm"]])).toBeUndefined();
    const home = tmp("home");
    mkdirSync(join(home, ".aws"));
    mkdirSync(join(home, ".kube"));
    const cfg = "[profile p]\ncredential_process = /opt/idp/creds --p\n";
    const kube = "users:\n- name: u\n  user:\n    exec:\n      command: kubelogin\n      args: [get-token]\n";
    writeFileSync(join(home, ".aws/config"), cfg);
    writeFileSync(join(home, ".kube/config"), kube);
    const ctx: Ctx = { home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined };
    const scanOf = async (): Promise<Scan> => ({ version: 1, host: "t", user: "t", home, at: 0, items: (await toolHelpers(ctx)).filter((i) => i.kind === "tool-exec"), texts: {}, gaps: {} });
    const baseline = await scanOf();
    const real = [process.execPath, CLI];
    writeFileSync(join(home, ".aws/config"), awsGateText(cfg, awsPlan("p", cfg, ""), real, WIN).text);
    writeFileSync(join(home, ".kube/config"), kubeGateText(kube, "u", real).text);
    const after = await scanOf();
    expect(after.items.map((i) => i.meta?.gated)).toEqual(["kubelogin get-token", "/opt/idp/creds --p"]);
    expect(await evaluate({ scan: after, baseline, malicious: [], secrets: [] })).toEqual([]);
    // The same wrapper by another program: a change, reported.
    writeFileSync(join(home, ".aws/config"), awsGateText(cfg, awsPlan("p", cfg, ""), [join(home, "Downloads", "vswarm")], WIN).text);
    const fake = await evaluate({ scan: await scanOf(), baseline, malicious: [], secrets: [] });
    expect(fake.map((f) => f.rule).sort()).toEqual(["tool-exec-changed", "tool-exec-risky"]);
    // A command that is itself risky is still judged by what it runs once gated.
    const risky = "[profile p]\ncredential_process = /tmp/x/creds\n";
    writeFileSync(join(home, ".aws/config"), awsGateText(risky, awsPlan("p", risky, ""), real, WIN).text);
    expect((await evaluate({ scan: await scanOf(), malicious: [], secrets: [] })).map((f) => f.rule)).toEqual(["tool-exec-risky"]);
  });
});
