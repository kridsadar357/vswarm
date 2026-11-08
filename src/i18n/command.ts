// `vswarm lang [th|en|auto]`: the language of the terminal and the dashboard, one setting for both (ui.json beside
// vswarm's state). VSWARM_LANG still wins for a single run or a shell.

import { c, line } from "../sec/print";
import { forgetLang, langFile, langSource, saveLang, systemLang, t, type Lang, type LangSetting } from ".";

const NAME = { th: "ไทย", en: "English" } as const;

export async function langCommand(args: string[]) {
  const [want, ...rest] = args;
  if (rest.length || (want !== undefined && !["th", "en", "auto"].includes(want))) throw new Error(t("cli.lang.usage"));
  if (want === undefined) {
    const s = langSource();
    const from = s.from === "env" ? t("cli.lang.fromEnv") : s.from === "saved" ? t("cli.lang.fromSaved") : t("cli.lang.fromDefault");
    line(`${t("cli.lang.now", { name: NAME[s.lang], lang: s.lang })} ${c.dim(`· ${[s.setting === "auto" ? t("cli.lang.auto") : "", from].filter(Boolean).join(", ")}`)}`);
    line(c.dim(`  ${t("cli.lang.change")}`));
    return;
  }
  saveLang(want as LangSetting);
  forgetLang();
  // Said in the language just chosen.
  const l: Lang = want === "auto" ? systemLang() : (want as Lang);
  line(`${c.green("✔")} ${t("cli.lang.saved", { name: NAME[l], lang: l }, l)} ${c.dim(want === "auto" ? `· ${t("cli.lang.auto", {}, l)}` : "")}`);
  line(c.dim(`  ${t("cli.lang.where", { file: langFile() }, l)}`));
  if (process.env.VSWARM_LANG) line(c.amber(`  ${t("cli.lang.envWins", { value: process.env.VSWARM_LANG }, l)}`));
}
