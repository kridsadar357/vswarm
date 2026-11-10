// CI only: the Windows end-to-end steps (.github/workflows/test.yml) run vswarm on the runner's real profile, with
// nobody at a desktop to answer the dialog that commands weakening protection show (src/sec/human.ts). This runs the
// command line in-process with the answer given, as the test preload does. It is not a way around the question on a
// machine you use: code that imports vswarm to answer for itself is code deliberately working around it, the same as
// editing ~/.ssh/config by hand, which the guide says this does not stop.
import { answerWith } from "../src/sec/human";

answerWith(async () => true);
const { main } = await import("../src/cli");
const { c } = await import("../src/sec/print");
await main().catch((err) => {
  console.error(`${c.red("✖")} ${err.message ?? err}`);
  process.exit(4);
});
