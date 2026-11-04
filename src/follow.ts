// Tails a JSONL event file, surviving truncation and partial lines.

import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";
import type { Stamped } from "./state";

/** Only the tail is replayed on start; older sessions are not worth rebuilding. */
const REPLAY_BYTES = 2 * 1024 * 1024;

export function follow(file: string, onEvents: (events: Stamped[], reset: boolean) => void, intervalMs = 150) {
  let offset = -1;
  let partial = "";

  const read = () => {
    if (!existsSync(file)) return;
    const size = statSync(file).size;
    let reset = false;
    if (offset < 0 || size < offset) {
      reset = true;
      offset = Math.max(0, size - REPLAY_BYTES);
      partial = "";
    }
    if (size === offset && !reset) return;
    const fd = openSync(file, "r");
    const buf = Buffer.alloc(size - offset);
    readSync(fd, buf, 0, buf.length, offset);
    closeSync(fd);
    const startedMidFile = reset && offset > 0;
    offset = size;
    const lines = (partial + buf.toString("utf8")).split("\n");
    partial = lines.pop() ?? "";
    if (startedMidFile) lines.shift(); // first line was cut by the replay window
    const events: Stamped[] = [];
    for (const l of lines) {
      if (!l.trim()) continue;
      try {
        events.push(JSON.parse(l));
      } catch {}
    }
    if (events.length || reset) onEvents(events, reset);
  };

  read();
  const timer = setInterval(read, intervalMs);
  return () => clearInterval(timer);
}
