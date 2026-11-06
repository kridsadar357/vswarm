// Regenerates src/sec/data/popular.json: the most-used package names, which typo-squatters imitate.
//   bun scripts/popular.ts [npm count] [pypi count]
//
// Sources (both public, both ranked by downloads):
//   npm   the `top` list of wooorm's npm-high-impact package (npm packages ranked by weekly downloads), at a pinned
//         version, from the npm registry's CDN mirror unpkg.com
//   PyPI  hugovk's top-pypi-packages (downloads over the last 30 days, from the PyPI BigQuery / ClickHouse dataset)
// The file records the sources, versions and date. Names shorter than 4 characters are kept but never matched
// (too many real packages sit one edit from "ms" or "ws"). Commit the result; vswarm never fetches it at run time.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const NPM_HIGH_IMPACT = "1.13.0";
const [npmCount = 2000, pypiCount = 1000] = process.argv.slice(2).map(Number);

async function get(url: string): Promise<string> {
  const r = await fetch(url, { headers: { "user-agent": "vswarm scripts/popular.ts" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
}

const npmUrl = `https://unpkg.com/npm-high-impact@${NPM_HIGH_IMPACT}/lib/top.js`;
// `export const top = ['semver', 'minimatch', …]`: the names, in order, read as data (never imported or run).
const npm = [...(await get(npmUrl)).matchAll(/^\s*'((?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+)',?$/gm)].map((m) => m[1]);
if (npm.length < npmCount) throw new Error(`npm-high-impact listed only ${npm.length} names`);

const pypiUrl = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json";
const pypiData = JSON.parse(await get(pypiUrl));
// PEP 503 names: lower case, runs of - _ . as one -.
const pypi = (pypiData.rows as { project: string }[]).map((r) => r.project.toLowerCase().replace(/[-_.]+/g, "-"));
if (pypi.length < pypiCount) throw new Error(`top-pypi-packages listed only ${pypi.length} names`);

const out = {
  generated: new Date().toISOString().slice(0, 10),
  sources: {
    npm: `${npmUrl} (npm-high-impact ${NPM_HIGH_IMPACT}, ranked by weekly downloads), first ${npmCount}`,
    pip: `${pypiUrl} (last_update ${pypiData.last_update}), first ${pypiCount}`,
  },
  npm: [...new Set(npm)].slice(0, npmCount),
  pip: [...new Set(pypi)].slice(0, pypiCount),
};
const file = join(import.meta.dir, "../src/sec/data/popular.json");
mkdirSync(dirname(file), { recursive: true });
writeFileSync(file, JSON.stringify(out, null, 0).replace(/,"/g, ',\n"') + "\n");
console.log(`${file}: ${out.npm.length} npm, ${out.pip.length} PyPI names (${out.generated})`);
