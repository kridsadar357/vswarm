// The launcher of the Windows try sandbox, run as its own bun process: `bun winbox.ts <spec.json>`.
//
// It starts one command in an AppContainer (the sandbox Edge and the Store apps run in): the code reads only what is
// open to every app (Windows, Program Files) and what vswarm granted the container (the box, toolchains, read-only),
// has no network unless the container is let through to vswarm's proxy, and cannot reach your profile, your other
// processes or their windows' input. Everything it starts is in a job object: when the command ends, what it left
// running is listed and stopped, and if this launcher is killed (a time limit), the job takes the whole tree with it.
//
// The wait blocks this process, not vswarm's: the proxy and the report stay in the parent. The exit code is the
// command's; what it left behind goes to spec.result.

import { dlopen, FFIType, ptr } from "bun:ffi";
import { readFileSync, writeFileSync } from "node:fs";

export interface BoxSpec {
  /** The AppContainer profile name; the parent made it, granted it the box and asked for its loopback exemption. */
  profile: string;
  /** The whole command line, quoted for CreateProcessW. */
  cmdline: string;
  cwd: string;
  /** A shell for you: it gets a console window of its own, never vswarm's (see below). */
  interactive?: boolean;
  env: Record<string, string>;
  /** Where the launcher writes { left: [{ pid, image }] }: processes still running after the command ended (then stopped). */
  result: string;
}

const W = (s: string) => Buffer.from(s + "\0", "utf16le");

function main(specFile: string): number {
  const spec = JSON.parse(readFileSync(specFile, "utf8")) as BoxSpec;
  const userenv = dlopen("userenv.dll", {
    DeriveAppContainerSidFromAppContainerName: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.i32 },
  });
  const k32 = dlopen("kernel32.dll", {
    InitializeProcThreadAttributeList: { args: [FFIType.ptr, FFIType.u32, FFIType.u32, FFIType.ptr], returns: FFIType.i32 },
    UpdateProcThreadAttribute: { args: [FFIType.ptr, FFIType.u32, FFIType.u64, FFIType.ptr, FFIType.u64, FFIType.ptr, FFIType.ptr], returns: FFIType.i32 },
    CreateProcessW: { args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.i32, FFIType.u32, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr], returns: FFIType.i32 },
    CreateJobObjectW: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.u64 },
    SetInformationJobObject: { args: [FFIType.u64, FFIType.u32, FFIType.ptr, FFIType.u32], returns: FFIType.i32 },
    AssignProcessToJobObject: { args: [FFIType.u64, FFIType.u64], returns: FFIType.i32 },
    QueryInformationJobObject: { args: [FFIType.u64, FFIType.u32, FFIType.ptr, FFIType.u32, FFIType.ptr], returns: FFIType.i32 },
    TerminateJobObject: { args: [FFIType.u64, FFIType.u32], returns: FFIType.i32 },
    ResumeThread: { args: [FFIType.u64], returns: FFIType.u32 },
    WaitForSingleObject: { args: [FFIType.u64, FFIType.u32], returns: FFIType.u32 },
    GetExitCodeProcess: { args: [FFIType.u64, FFIType.ptr], returns: FFIType.i32 },
    GetStdHandle: { args: [FFIType.i32], returns: FFIType.u64 },
    SetHandleInformation: { args: [FFIType.u64, FFIType.u32, FFIType.u32], returns: FFIType.i32 },
    CloseHandle: { args: [FFIType.u64], returns: FFIType.i32 },
    GetLastError: { args: [], returns: FFIType.u32 },
    OpenProcess: { args: [FFIType.u32, FFIType.i32, FFIType.u32], returns: FFIType.u64 },
    QueryFullProcessImageNameW: { args: [FFIType.u64, FFIType.u32, FFIType.ptr, FFIType.ptr], returns: FFIType.i32 },
  });
  const fail = (what: string) => {
    process.stderr.write(`vswarm try: the Windows sandbox did not start (${what}, error ${k32.symbols.GetLastError()})\n`);
    return 125;
  };

  const sidOut = new BigUint64Array(1);
  if (userenv.symbols.DeriveAppContainerSidFromAppContainerName(ptr(W(spec.profile)), ptr(sidOut)) !== 0) return fail("no AppContainer profile");

  // No capabilities: no internet, no private network, no library folders. The proxy is reached on loopback only,
  // and only when the profile has the loopback exemption.
  const caps = Buffer.alloc(24);
  caps.writeBigUInt64LE(sidOut[0], 0);

  // Never your console: code that shares it can type into it (WriteConsoleInput), and what it typed runs in your
  // shell after vswarm exits. A shell for you gets a console window of its own; a command gets no console at all and
  // the three standard handles (vswarm's pipes) inherited, nothing else (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
  const std = spec.interactive ? [] : [-10, -11, -12].map((n) => k32.symbols.GetStdHandle(n));
  const handles = [...new Set(std.filter((h) => h !== 0n && h !== 0xffffffffffffffffn))];
  for (const h of handles) k32.symbols.SetHandleInformation(h, 1, 1);
  const list = new BigUint64Array(Math.max(handles.length, 1));
  handles.forEach((h, i) => (list[i] = h));

  const size = new BigUint64Array(1);
  const attrs = handles.length ? 2 : 1;
  k32.symbols.InitializeProcThreadAttributeList(null, attrs, 0, ptr(size));
  const attrList = Buffer.alloc(Number(size[0]));
  if (!k32.symbols.InitializeProcThreadAttributeList(ptr(attrList), attrs, 0, ptr(size))) return fail("attribute list");
  if (!k32.symbols.UpdateProcThreadAttribute(ptr(attrList), 0, 0x00020009n, ptr(caps), 24n, null, null)) return fail("security capabilities");
  if (handles.length && !k32.symbols.UpdateProcThreadAttribute(ptr(attrList), 0, 0x00020002n, ptr(list), BigInt(handles.length * 8), null, null)) return fail("handle list");

  // STARTUPINFOEXW (x64): cb, …, dwFlags at 60, hStdInput/Output/Error at 80/88/96, lpAttributeList at 104.
  const si = Buffer.alloc(112);
  si.writeUInt32LE(112, 0);
  if (!spec.interactive) {
    si.writeUInt32LE(0x100, 60); // STARTF_USESTDHANDLES
    std.forEach((h, i) => si.writeBigUInt64LE(h, 80 + i * 8));
  }
  si.writeBigUInt64LE(BigInt(ptr(attrList)), 104);

  // The environment block: KEY=value pairs, sorted, each ended by a NUL, the block by another.
  const env = Object.entries(spec.env).sort(([a], [b]) => a.toUpperCase().localeCompare(b.toUpperCase())).map(([k, v]) => `${k}=${v}\0`).join("") + "\0";

  // A job that ends every process in it when its last handle closes: this launcher's, at exit or when killed.
  const job = k32.symbols.CreateJobObjectW(null, null);
  if (!job) return fail("job object");
  const limits = Buffer.alloc(144); // JOBOBJECT_EXTENDED_LIMIT_INFORMATION; LimitFlags at 16
  limits.writeUInt32LE(0x2000, 16); // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
  if (!k32.symbols.SetInformationJobObject(job, 9, ptr(limits), 144)) return fail("job limits");

  const pi = Buffer.alloc(24);
  const flags = 0x00080000 /* EXTENDED_STARTUPINFO_PRESENT */ | 0x400 /* CREATE_UNICODE_ENVIRONMENT */ | 0x4 /* CREATE_SUSPENDED */ |
    (spec.interactive ? 0x10 /* CREATE_NEW_CONSOLE */ : 0x08000000); /* CREATE_NO_WINDOW */
  if (!k32.symbols.CreateProcessW(null, ptr(W(spec.cmdline)), null, null, handles.length ? 1 : 0, flags, ptr(Buffer.from(env, "utf16le")), ptr(W(spec.cwd)), ptr(si), ptr(pi))) return fail("CreateProcessW");
  const proc = pi.readBigUInt64LE(0), thread = pi.readBigUInt64LE(8);
  // Into the job before it runs a single instruction, so nothing it starts escapes it.
  if (!k32.symbols.AssignProcessToJobObject(job, proc)) {
    k32.symbols.TerminateJobObject(job, 1);
    return fail("job assignment");
  }
  // VSWARM_WINBOX_DEBUG=1: each step on stderr (the CI runner has no other window into this).
  const debug = process.env.VSWARM_WINBOX_DEBUG ? (t: string) => process.stderr.write(`winbox ${Date.now()} ${t}\n`) : () => {};
  k32.symbols.ResumeThread(thread);
  debug("resumed");
  k32.symbols.WaitForSingleObject(proc, 0xffffffff);
  debug("command ended");
  const code = new Uint32Array(1);
  k32.symbols.GetExitCodeProcess(proc, ptr(code));

  // JOBOBJECT_BASIC_PROCESS_ID_LIST: what is still running, named by its program; then all of it is stopped.
  const ids = Buffer.alloc(8 + 8 * 256);
  const left: { pid: number; image: string }[] = [];
  const listed = k32.symbols.QueryInformationJobObject(job, 3, ptr(ids), ids.length, null);
  debug(`job list ${listed} error ${k32.symbols.GetLastError()} assigned ${ids.readUInt32LE(0)} listed ${ids.readUInt32LE(4)}`);
  if (listed || k32.symbols.GetLastError() === 234) {
    const n = ids.readUInt32LE(4);
    for (let i = 0; i < Math.min(n, 256); i++) {
      const pid = Number(ids.readBigUInt64LE(8 + i * 8));
      const h = k32.symbols.OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, 0, pid);
      const name = Buffer.alloc(1040), len = new Uint32Array([520]);
      const image = h && k32.symbols.QueryFullProcessImageNameW(h, 0, ptr(name), ptr(len)) ? name.toString("utf16le", 0, len[0] * 2) : "";
      if (h) k32.symbols.CloseHandle(h);
      left.push({ pid, image });
    }
  }
  k32.symbols.TerminateJobObject(job, 1);
  try {
    writeFileSync(spec.result, JSON.stringify({ left }) + "\n");
  } catch {}
  for (const h of [proc, thread, job]) k32.symbols.CloseHandle(h);
  debug("done");
  return code[0];
}

// Only when run as the launcher; importing this file (types, tests) runs nothing.
if (import.meta.main) process.exit(main(process.argv[2]));
