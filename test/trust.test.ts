// What vswarm's own trust rests on: the installers' pinned Bun, the seals on its state files and incident log, signed
// posture reports and team policy. Nothing here touches the real home, Keychain, secret service or DPAPI: keys live
// in temp files, and the CLI runs with its state in a temp folder.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const WIN = process.platform === "win32";

describe("installers: Bun is pinned, not piped", () => {
  const sh = readFileSync(join(ROOT, "install.sh"), "utf8");
  const ps = readFileSync(join(ROOT, "install.ps1"), "utf8");

  test("one Bun version in both scripts, and a SHA-256 for every platform the scripts pick", () => {
    const shVersion = /^BUN_VERSION=(\S+)$/m.exec(sh)?.[1];
    const psVersion = /\$BunVersion = '([^']+)'/.exec(ps)?.[1];
    expect(shVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(psVersion).toBe(shVersion!);
    const shPins = Object.fromEntries([...sh.matchAll(/^\s+(bun-[\w-]+)\) echo ([0-9a-f]+) ;;$/gm)].map((m) => [m[1], m[2]]));
    const psPins = Object.fromEntries([...ps.matchAll(/'(bun-windows-[\w-]+)'\s*=\s*'([0-9a-f]+)'/g)].map((m) => [m[1], m[2]]));
    const unix = ["bun-darwin-aarch64", "bun-darwin-x64", "bun-darwin-x64-baseline", "bun-linux-aarch64", "bun-linux-aarch64-musl",
      "bun-linux-x64", "bun-linux-x64-baseline", "bun-linux-x64-musl", "bun-linux-x64-musl-baseline"];
    expect(Object.keys(shPins).sort()).toEqual(unix.sort());
    expect(Object.keys(psPins).sort()).toEqual(["bun-windows-aarch64", "bun-windows-x64", "bun-windows-x64-baseline"]);
    for (const h of [...Object.values(shPins), ...Object.values(psPins)]) expect(h).toMatch(/^[0-9a-f]{64}$/);
    // Every pin is its own: a copy-paste slip would give two zips one hash.
    expect(new Set([...Object.values(shPins), ...Object.values(psPins)]).size).toBe(unix.length + 3);
    // The download names the pinned version, and a mismatch stops before anything is unpacked.
    expect(sh).toContain("releases/download/bun-v$BUN_VERSION/$asset.zip");
    expect(sh.indexOf('[ "$got" = "$want" ]')).toBeLessThan(sh.indexOf("unzip -q"));
    expect(ps).toContain("releases/download/bun-v$BunVersion/$Asset.zip");
    expect(ps.indexOf("$Got -ne $BunSha256[$Asset]")).toBeLessThan(ps.indexOf("Expand-Archive"));
  });

  test("no script from the network goes into a shell for Bun", () => {
    const code = (t: string) => t.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    expect(code(sh)).not.toMatch(/bun\.sh\/install/);
    expect(code(sh)).not.toMatch(/curl[^\n]*\|\s*(ba)?sh/);
    expect(code(ps)).not.toMatch(/bun\.sh\/install/);
    expect(code(ps)).not.toMatch(/\[scriptblock\]::Create|Invoke-RestMethod|\|\s*iex\b/i);
    // An existing Bun is still used first.
    expect(sh.indexOf("command -v bun")).toBeLessThan(sh.indexOf("install_bun\n  BUN="));
    expect(ps.indexOf("Get-Command bun")).toBeLessThan(ps.indexOf("$BunSha256 = @{"));
  });

  test.skipIf(WIN)("install.sh picks the zip for each system and CPU", async () => {
    const pick = async (s: string, m: string) => {
      const script = `VSWARM_INSTALL_LIB=1\n. "$0"\nuname() { case "$1" in -s) echo ${s};; -m) echo ${m};; esac; }\nsysctl() { echo 0; }\nbun_asset || echo none`;
      const p = Bun.spawn(["sh", "-c", script, join(ROOT, "install.sh")], { stdout: "pipe", stderr: "pipe" });
      return (await new Response(p.stdout).text()).trim();
    };
    expect(await pick("Darwin", "arm64")).toBe("bun-darwin-aarch64");
    // sysctl answers "0" here, so no AVX2 is seen: the baseline build.
    expect(await pick("Darwin", "x86_64")).toBe("bun-darwin-x64-baseline");
    expect(["bun-linux-aarch64", "bun-linux-aarch64-musl"]).toContain(await pick("Linux", "aarch64"));
    expect(await pick("Linux", "x86_64")).toMatch(/^bun-linux-x64(-musl)?(-baseline)?$/);
    expect(await pick("FreeBSD", "amd64")).toBe("none");
    expect(await pick("Linux", "riscv64")).toBe("none");
  });
});
