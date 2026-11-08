// vswarm try's walls: a /proc of the sandbox's own on Linux or no sandbox at all, the macOS Seatbelt denials, and a
// proxy that never leads back into this machine or its cloud. The only connections go to 127.0.0.1 ports opened here;
// names resolve through stand-ins.
import { describe, expect, test } from "bun:test";
import { forbiddenAddress, startProxy } from "../src/sec/try/proxy";
import { bwrapArgs, NO_FRESH_PROC } from "../src/sec/try/linux";
import { profile, type Box } from "../src/sec/try/sandbox";

describe("try: the walls", () => {
  const box: Box = { dir: "/b", work: "/b/work", home: "/b/home", tmp: "/b/tmp", netlog: "/b/tmp/n" };

  test("Linux: always a fresh /proc of the sandbox's own, never the host's; where none can be had, it does not run", () => {
    const a = bwrapArgs("/home/u", box, { tools: [], bun: "/usr/bin/bun", interactive: false });
    expect(a.join(" ")).toContain("--proc /proc");
    expect(a.join(" ")).not.toContain("--ro-bind /proc /proc");
    expect(NO_FRESH_PROC).toContain("/proc/<pid>/root");
    expect(NO_FRESH_PROC).toContain("systempaths=unconfined");
  });

  test("macOS: no background downloads by the system for it, no Spotlight index", () => {
    const p = profile("/Users/t", box, 1);
    expect(p).toContain('(global-name "com.apple.nsurlsessiond")');
    expect(p).toContain('(global-name "com.apple.metadata.mds")');
  });

  test("the proxy: loopback, link-local and cloud metadata addresses are refused, by name or by address; --localhost opens loopback only", async () => {
    expect(forbiddenAddress("127.0.0.1")).toContain("loopback");
    expect(forbiddenAddress("::1")).toContain("loopback");
    expect(forbiddenAddress("::ffff:127.0.0.2")).toContain("loopback");
    expect(forbiddenAddress("0.0.0.0")).toContain("loopback");
    expect(forbiddenAddress("169.254.169.254", true)).toContain("metadata");
    expect(forbiddenAddress("169.254.10.1", true)).toContain("link-local");
    expect(forbiddenAddress("fe80::1", true)).toContain("link-local");
    expect(forbiddenAddress("fd00:ec2::254", true)).toContain("metadata");
    expect(forbiddenAddress("100.100.100.200", true)).toContain("metadata");
    expect(forbiddenAddress("127.0.0.1", true)).toBeUndefined();
    expect(forbiddenAddress("93.184.216.34")).toBeUndefined();
    const upstream = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data(s) { s.write("pong"); }, open() {} } });
    // A public-looking name that resolves to this machine (DNS rebinding): refused by what it resolves to.
    const names: Record<string, string[]> = { "rebind.example": ["127.0.0.1"], "meta.example": ["169.254.169.254"], "ok.example": ["127.0.0.1"] };
    const ask = async (p: number, target: string) => {
      const c = await Bun.connect({ hostname: "127.0.0.1", port: p, socket: { data(s, d) { (s as any).got = ((s as any).got ?? "") + Buffer.from(d).toString(); }, open() {} } });
      c.write(`CONNECT ${target} HTTP/1.1\r\n\r\n`);
      await Bun.sleep(300);
      const got = (c as any).got ?? "";
      c.end();
      return got as string;
    };
    const strict = startProxy(() => true, { resolve: async (h) => names[h] ?? [] });
    const open = startProxy(() => true, { localhost: true, resolve: async (h) => names[h] ?? [] });
    try {
      expect(await ask(strict.port, `127.0.0.1:${upstream.port}`)).toContain("403");
      expect(await ask(strict.port, `rebind.example:${upstream.port}`)).toContain("is this machine (loopback)");
      expect(await ask(strict.port, "meta.example:80")).toContain("cloud metadata");
      expect(await ask(strict.port, "nowhere.example:80")).toContain("does not resolve");
      expect(strict.hits.every((h) => !h.allowed)).toBe(true);
      expect(await ask(open.port, `ok.example:${upstream.port}`)).toContain("200 Connection Established");
      expect(await ask(open.port, "meta.example:80")).toContain("403");
    } finally {
      strict.stop();
      open.stop();
      upstream.stop(true);
    }
  });
});
