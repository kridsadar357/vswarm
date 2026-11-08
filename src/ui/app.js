// vswarm ui: the page. No framework, no build step, nothing from the network but this machine's own server.
// Every piece of data is put into the page as text (textContent / text nodes); none of it is ever parsed as HTML.
// The key for this run comes from the URL fragment (#t=…), which the browser never sends anywhere; it is kept in
// memory and sent back in the Authorization header. In a report made by `vswarm report --html` the data and both
// language files are in the page itself and there is no server: nothing is fetched and there are no actions.
"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const embedded = $("vswarm-data");
  const REPORT = !!embedded;
  const token = (/[#&]t=([A-Za-z0-9_-]{20,100})/.exec(location.hash) || [])[1] || "";

  let dicts = { en: {}, th: {} };
  let dash = null;
  let lang = "en";
  let busy = false;
  let stopped = false;
  const open = new Set();
  const showAll = new Set();

  // ── DOM helpers: text only

  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) e.append(kid instanceof Node ? kid : String(kid));
    return e;
  }

  const NS = "http://www.w3.org/2000/svg";
  const ICONS = {
    safe: ["M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6z", "m8.6 12 2.4 2.4 4.4-4.8"],
    check: ["M10.3 4.3 2.6 17.6A2 2 0 0 0 4.3 20.6h15.4a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z", "M12 9.5v4.2", "M12 17h.01"],
    stop: ["M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z", "M9 9l6 6", "M15 9l-6 6"],
    good: [{ c: [12, 12, 9] }, "m8.3 12.2 2.5 2.5 4.9-5.2"],
    warn: ["M10.3 4.3 2.6 17.6A2 2 0 0 0 4.3 20.6h15.4a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z", "M12 9.5v4.2", "M12 17h.01"],
    bad: ["M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z", "M9.5 9.5l5 5", "M14.5 9.5l-5 5"],
    off: [{ c: [12, 12, 9] }, "M8 12h8"],
    info: [{ c: [12, 12, 9] }, "M12 11v5", "M12 8h.01"],
    watch: ["M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z", { c: [12, 12, 3] }],
    guard: ["M21 8 12 3 3 8v8l9 5 9-5z", "M3 8l9 5 9-5", "M12 13v8"],
    keys: [{ c: [7.5, 15.5, 4.5] }, "M10.7 12.3 20 3", "M16 7l3 3", "M18 5l2 2"],
    doors: ["M6 21V4.5A1.5 1.5 0 0 1 7.5 3h9A1.5 1.5 0 0 1 18 4.5V21", "M3.5 21h17", "M14.5 12.5h.01"],
    ai: ["M12 3l1.8 4.7 4.7 1.8-4.7 1.8L12 16l-1.8-4.7L5.5 9.5l4.7-1.8z", "M18.5 14.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z"],
    seal: [{ r: [4.5, 10.5, 15, 10.5, 2.5] }, "M8 10.5V7.5a4 4 0 0 1 8 0v3", "M12 14.5v2.5"],
    refresh: ["M20.5 12a8.5 8.5 0 1 1-2.5-6", "M20.5 4v4.5H16"],
    clock: [{ c: [12, 12, 9] }, "M12 7.5V12l3 2"],
    base: ["M4 20h16", "M6 20V10l6-5 6 5v10", "M10 20v-5h4v5"],
    list: ["M8 6h12", "M8 12h12", "M8 18h12", "M4 6h.01", "M4 12h.01", "M4 18h.01"],
    sun: [{ c: [12, 12, 4] }, "M12 2.5v2", "M12 19.5v2", "M4.6 4.6l1.4 1.4", "M18 18l1.4 1.4", "M2.5 12h2", "M19.5 12h2", "M4.6 19.4 6 18", "M18 6l1.4-1.4"],
    moon: ["M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"],
    auto: [{ c: [12, 12, 8.5] }, "M12 3.5v17a8.5 8.5 0 0 0 0-17z"],
    term: [{ r: [3, 4.5, 18, 15, 2.5] }, "m7 9.5 3 2.5-3 2.5", "M12.5 15h4.5"],
  };
  function icon(name, cls) {
    const s = document.createElementNS(NS, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("fill", "none");
    s.setAttribute("stroke", "currentColor");
    s.setAttribute("stroke-width", "1.9");
    s.setAttribute("stroke-linecap", "round");
    s.setAttribute("stroke-linejoin", "round");
    s.setAttribute("aria-hidden", "true");
    if (cls) s.setAttribute("class", cls);
    for (const p of ICONS[name] || []) {
      let e;
      if (typeof p === "string") (e = document.createElementNS(NS, "path")), e.setAttribute("d", p);
      else if (p.c) (e = document.createElementNS(NS, "circle")), e.setAttribute("cx", p.c[0]), e.setAttribute("cy", p.c[1]), e.setAttribute("r", p.c[2]);
      else (e = document.createElementNS(NS, "rect")), e.setAttribute("x", p.r[0]), e.setAttribute("y", p.r[1]), e.setAttribute("width", p.r[2]), e.setAttribute("height", p.r[3]), e.setAttribute("rx", p.r[4]);
      s.append(e);
    }
    return s;
  }

  // ── words

  const locale = () => (lang === "th" ? "th-TH" : "en-GB");
  function when(ms) {
    if (!ms) return "";
    const d = new Date(ms);
    const ref = new Date(REPORT && dash ? dash.at : Date.now());
    const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const time = d.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" });
    const diff = Math.round((day(ref) - day(d)) / 86400000);
    if (diff === 0) return `${t("day.today")} ${time}`;
    if (diff === 1) return `${t("day.yesterday")} ${time}`;
    return d.toLocaleString(locale(), { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function word(v) {
    return ["pass", "warn", "block"].includes(v) ? t(`verdict.${v}`) : v;
  }
  /** A sentence from the language files; {at} is a time, {verdict} a verdict, the rest as given. */
  function t(key, p) {
    let s = dicts[lang][key] ?? dicts.en[key];
    if (s === undefined) return key;
    // {n:thing|things}: the first form when n is 1 (English only; Thai has no plural).
    s = s.replace(/\{(\w+):([^|}]*)\|([^}]*)\}/g, (m, k, one, many) => (p && Number(p[k]) === 1 ? one : many));
    return s.replace(/\{(\w+)\}/g, (m, k) => {
      if (!p || p[k] === undefined || p[k] === null) return "";
      if (k === "at") return when(Number(p[k]));
      if (k === "verdict") return word(String(p[k]));
      if (typeof p[k] === "number") return p[k].toLocaleString(locale());
      return String(p[k]);
    });
  }
  const has = (key) => dicts[lang][key] !== undefined || dicts.en[key] !== undefined;
  /** The plain sentence for a rule; a generic one when the rule is unknown or a name it needs is missing. */
  function ruleText(rule, group, part, p) {
    const k = `rule.${rule}.${part}`;
    const tpl = dicts[lang][k] ?? dicts.en[k];
    const needs = tpl ? [...tpl.matchAll(/\{(\w+)\}/g)].map((m) => m[1]) : [];
    if (tpl && needs.every((n) => p && p[n])) return t(k, p);
    return t(`rule._${group}.${part}`, p);
  }
  const say = (s) => (s ? t(s.key, s.p) : "");

  // ── talking to the server

  async function api(path, body, poll) {
    const headers = { Authorization: `Bearer ${token}` };
    if (body) headers["Content-Type"] = "application/json";
    if (poll) headers["X-Vswarm-Poll"] = "1";
    let r;
    try {
      r = await fetch(path, { method: body ? "POST" : "GET", headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
    } catch {
      gone();
      throw new Error("stopped");
    }
    if (r.status === 401) {
      banner(t("app.needLink"));
      throw new Error("needs the link");
    }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  function gone() {
    stopped = true;
    banner(t("app.stopped"));
  }
  function banner(text) {
    const b = $("banner");
    b.textContent = text;
    b.hidden = !text;
  }
  let toastTimer;
  function toast(text) {
    const e = $("toast");
    e.textContent = text;
    e.classList.add("on");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => e.classList.remove("on"), 2600);
  }

  function confirmBox(title, body, yes) {
    const d = $("dlg");
    $("dlg-title").textContent = title;
    $("dlg-body").textContent = body;
    $("dlg-yes").textContent = yes || t("btn.ok");
    $("dlg-no").textContent = t("btn.cancel");
    return new Promise((resolve) => {
      const done = (v) => {
        $("dlg-yes").onclick = $("dlg-no").onclick = d.oncancel = null;
        if (d.open) d.close();
        resolve(v);
      };
      $("dlg-yes").onclick = () => done(true);
      $("dlg-no").onclick = () => done(false);
      d.oncancel = () => done(false);
      d.showModal();
      $("dlg-no").focus();
    });
  }

  async function copy(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const r = document.createRange();
      r.selectNodeContents(btn.previousSibling);
      const s = getSelection();
      s.removeAllRanges();
      s.addRange(r);
    }
    btn.textContent = t("btn.copied");
    setTimeout(() => (btn.textContent = t("btn.copy")), 1600);
  }
  const cmdBox = (cmd) => {
    const code = el("code", { text: cmd, translate: "no" });
    const b = el("button", { type: "button", text: t("btn.copy"), "aria-label": `${t("btn.copy")}: ${cmd}` });
    b.addEventListener("click", () => copy(cmd, b));
    return el("div", { class: "cmd" }, code, b);
  };

  // ── actions

  async function runCheck() {
    if (busy || REPORT) return;
    if (!(await confirmBox(t("confirm.check.title"), t("confirm.check.body"), t("btn.check")))) return;
    busy = true;
    render();
    try {
      dash = await api("/api/check", {});
    } catch (e) {
      if (!stopped) toast(t("app.error", { why: e.message }));
    } finally {
      busy = false;
      render();
    }
  }
  async function markMine(card) {
    if (REPORT) return;
    const title = ruleText(card.rule, card.group, "what", card.p);
    if (!(await confirmBox(t("confirm.mine.title"), t("confirm.mine.body", { title }), t("btn.mine")))) return;
    try {
      dash = await api("/api/accept", { ref: card.ref });
      toast(`${t("btn.mine")} ✓`);
      render();
    } catch (e) {
      if (!stopped) toast(t("app.error", { why: e.message }));
    }
  }
  async function setLang(l) {
    if (l === lang) return;
    lang = l;
    render();
    if (!REPORT && token) api("/api/lang", { lang: l }).catch(() => {});
  }

  // ── theme (a per-viewer convenience: browser storage, never the key)

  const THEMES = ["auto", "light", "dark"];
  let theme = "auto";
  try {
    theme = THEMES.includes(localStorage.getItem("vswarm-theme")) ? localStorage.getItem("vswarm-theme") : "auto";
  } catch {}
  // #…&theme=dark in the link: for that view only (screenshots), not remembered.
  const hashTheme = (/[#&]theme=(light|dark)/.exec(location.hash) || [])[1];
  if (hashTheme) theme = hashTheme;
  function applyTheme() {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    const b = $("theme");
    b.replaceChildren(icon(theme === "auto" ? "auto" : theme === "light" ? "sun" : "moon"));
    const label = `${t("set.theme")}: ${t(`set.theme.${theme}`)}`;
    b.setAttribute("aria-label", label);
    b.title = label;
  }
  $("theme").addEventListener("click", () => {
    theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
    try {
      localStorage.setItem("vswarm-theme", theme);
    } catch {}
    applyTheme();
  });
  for (const b of document.querySelectorAll("#lang button")) b.addEventListener("click", () => setLang(b.dataset.lang));

  // ── rendering

  function head(id, title, sub) {
    return el("div", { class: "block__head" }, el("h2", { id, text: title }), sub ? el("p", { text: sub }) : null);
  }

  function renderHero() {
    const s = dash.status;
    const hero = $("hero");
    hero.className = `hero hero--${s.level}`;
    const meta = el("div", { class: "hero__meta" },
      el("span", {}, icon("clock"), s.checkedAt ? t("status.checked", { at: s.checkedAt }) : t("status.never")),
      s.items ? el("span", {}, icon("list"), t("status.items", { n: s.items })) : null,
      s.baselineAt ? el("span", {}, icon("base"), t("status.baseline", { at: s.baselineAt })) : null,
    );
    const btn = REPORT ? el("span", { class: "report-note" }, icon("info"), t("app.report", { at: dash.at }))
      : el("button", { type: "button", class: "btn btn--primary", onclick: runCheck, disabled: busy || stopped }, icon("refresh", busy ? "spin" : ""), busy ? t("btn.checking") : t("btn.check"));
    hero.replaceChildren(
      el("div", { class: "hero__badge" }, icon(s.level)),
      el("div", {},
        el("p", { class: "hero__kicker", text: t("app.tagline") }),
        el("h1", { class: "hero__title", text: t(`level.${s.level}`) }),
        el("p", { class: "hero__why", text: say(s.why) }),
        s.extra.length ? el("ul", { class: "hero__extra" }, s.extra.map((x) => el("li", { text: say(x) }))) : null,
      ),
      el("div", { class: "hero__foot" }, meta, btn),
    );
  }

  const SEV_ICON = { critical: "bad", high: "bad", medium: "warn", low: "info", info: "info" };
  function renderCard(c) {
    const opened = open.has(c.ref);
    const tech = el("div", { class: "tech", id: `tech-${c.ref}`, hidden: !opened },
      el("b", { text: c.title }),
      c.detail.map((d) => el("span", { text: d })),
      c.fix ? el("span", { text: `→ ${c.fix}` }) : null,
    );
    const toggle = el("button", { type: "button", class: "link", "aria-expanded": String(opened), "aria-controls": `tech-${c.ref}`, text: opened ? t("btn.less") : t("btn.more") });
    toggle.addEventListener("click", () => {
      if (open.has(c.ref)) open.delete(c.ref);
      else open.add(c.ref);
      render();
    });
    const actions = el("div", { class: "card__actions" },
      !REPORT && c.canAccept && c.group !== "info" ? el("button", { type: "button", class: "btn btn--soft btn--small", onclick: () => markMine(c) }, t("btn.mine")) : null,
      !c.canAccept && c.group === "action" ? el("span", { class: "card__note", text: t("card.cantMine") }) : null,
      toggle,
    );
    return el("article", { class: "card" },
      el("div", { class: "card__top" },
        el("h4", { text: ruleText(c.rule, c.group, "what", c.p) }),
      ),
      el("div", {}, el("span", { class: "chip" }, icon(SEV_ICON[c.severity] || "info"), t(`sev.${c.severity}`))),
      el("dl", {},
        el("dt", { text: t("card.why") }), el("dd", { text: ruleText(c.rule, c.group, "why", c.p) }),
        el("dt", { text: t("card.todo") }), el("dd", { text: ruleText(c.rule, c.group, "todo", c.p) }),
      ),
      tech,
      actions,
    );
  }

  function renderFindings() {
    const box = $("findings");
    const parts = [head("h-findings", t("sec.findings"))];
    const groups = [["action", "stop"], ["yours", "check"], ["info", "info"]];
    let any = false;
    for (const [g, ic] of groups) {
      const cards = dash.cards.filter((c) => c.group === g);
      if (!cards.length) continue;
      any = true;
      const limit = showAll.has(g) ? cards.length : g === "info" ? 3 : 6;
      parts.push(el("div", { class: `group group--${g}` },
        el("div", { class: "group__head" }, icon(ic, "group__icon"), el("h3", { text: t(`group.${g}`) }), el("span", { class: "group__count", text: String(cards.length) })),
        el("p", { class: "group__sub", text: t(`group.${g}.sub`) }),
        el("div", { class: "cards" }, cards.slice(0, limit).map(renderCard)),
        cards.length > limit ? el("button", { type: "button", class: "btn btn--ghost btn--small more", onclick: () => (showAll.add(g), render()) }, t("group.more", { n: cards.length - limit })) : null,
      ));
    }
    if (!any) parts.push(el("div", { class: "empty" }, icon(dash.status.checkedAt ? "good" : "info"), dash.status.checkedAt ? t("group.empty") : t("group.emptyNever")));
    box.replaceChildren(...parts);
  }

  function renderTiles() {
    const box = $("tiles");
    const tiles = dash.tiles.map((x) => el("div", { class: `tile tone--${x.tone}` },
      el("div", { class: "tile__head" },
        el("span", { class: "tile__icon" }, icon(x.key)),
        el("span", { class: "tile__title", text: t(`tile.${x.key}.title`) }),
        el("span", { class: "pill" }, icon(x.tone), t(`tone.${x.tone}`)),
      ),
      el("div", { class: "tile__state", text: say(x.say) }),
      x.lines.length ? el("ul", {}, x.lines.map((l) => el("li", { text: say(l) + (l.p && l.p.confirm ? t("tile.keys.confirm") : "") }))) : null,
      x.cmd ? cmdBox(x.cmd) : null,
    ));
    box.replaceChildren(head("h-tiles", t("sec.tiles")), el("div", { class: "tiles" }, tiles));
  }

  function eventText(e) {
    if (e.say.key === "ev.found") return ruleText(e.say.p.rule, "yours", "what", e.say.p);
    const p = { ...e.say.p };
    if ("key" in p && !p.key) p.key = t("word.aKey");
    if (p.whyKey) p.why = t(`refuse.${p.whyKey}`);
    return t(e.say.key, p);
  }
  function renderTimeline() {
    const box = $("timeline");
    const all = dash.timeline;
    const limit = showAll.has("timeline") ? all.length : 10;
    const list = all.length ? el("ul", { class: "tl" }, all.slice(0, limit).map((e) => el("li", { class: `tone--${e.tone}` },
      icon(e.tone, "tl__dot"),
      el("span", { class: "tl__when", text: when(e.at) }),
      el("span", { class: "tl__what", text: eventText(e) }),
    ))) : el("div", { class: "tl" }, el("p", { class: "tl__empty", text: t("timeline.empty") }));
    box.replaceChildren(head("h-timeline", t("sec.timeline")), list,
      all.length > limit ? el("button", { type: "button", class: "btn btn--ghost btn--small more", onclick: () => (showAll.add("timeline"), render()) }, t("group.more", { n: all.length - limit })) : null);
  }

  const TERMINAL = [
    ["term.respond", "vswarm respond"], ["term.diff", "vswarm diff"], ["term.baseline", "vswarm baseline"], ["term.unlock", "vswarm unlock"],
    ["term.watch", "vswarm watch on"], ["term.guard", "vswarm guard on"], ["term.gate", 'vswarm gate ssh "prod-*"'],
    ["term.protect", "vswarm agent protect ~/.ssh/<key>"], ["term.unprotect", "vswarm agent unprotect <key>"], ["term.inspect", "vswarm agents --inspect"],
    ["term.accept", "vswarm accept --list"], ["term.uninstall", "vswarm uninstall"],
  ];
  function renderTerminal() {
    $("terminal").replaceChildren(head("h-terminal", t("sec.terminal")), el("div", { class: "term" },
      el("p", { text: t("term.intro") }),
      TERMINAL.map(([k, cmd]) => el("div", { class: "term__row" }, el("span", { text: t(k) }), cmdBox(cmd))),
    ));
  }

  function renderAbout() {
    const lv = (l, cls) => el("div", { class: `lv tone--${cls}` }, icon(l), t(`level.${l}`));
    $("about").replaceChildren(head("h-about", t("sec.about")), el("div", { class: "about" },
      el("p", { text: t("about.p1") }), el("p", { text: t("about.p2") }),
      el("div", { class: "levels" }, lv("safe", "good"), lv("check", "warn"), lv("stop", "bad")),
      el("p", { text: t("about.levels") }), el("p", { text: t("about.p3") }),
    ));
  }

  function render() {
    document.documentElement.lang = lang;
    for (const b of document.querySelectorAll("#lang button")) b.setAttribute("aria-pressed", String(b.dataset.lang === lang));
    applyTheme();
    for (const n of document.querySelectorAll("[data-i18n]")) n.textContent = t(n.dataset.i18n);
    if (!dash) return;
    document.title = `${t(`level.${dash.status.level}`)} · vswarm`;
    $("host").textContent = dash.host || "";
    renderHero();
    renderFindings();
    renderTiles();
    renderTimeline();
    renderTerminal();
    renderAbout();
    $("foot").replaceChildren(el("span", { text: REPORT ? t("foot.report") : t("foot.local") }), el("span", { text: `vswarm ${dash.version}` }));
  }

  // ── start

  $("brand-mark").append(icon("safe"));
  async function start() {
    if (REPORT) {
      const data = JSON.parse(embedded.textContent);
      dicts = data.i18n;
      dash = data.dash;
      lang = dash.lang;
      render();
      return;
    }
    const [en, th] = await Promise.all(["en", "th"].map((l) => fetch(`i18n/${l}.json`, { cache: "no-store" }).then((r) => r.json())));
    dicts = { en, th };
    lang = /^th/i.test(navigator.language || "") ? "th" : "en";
    render();
    if (!token) return banner(t("app.needLink"));
    try {
      dash = await api("/api/state");
      lang = dash.lang;
      render();
    } catch {}
    // A quiet refresh while the page is in view; it does not count as use, so the server can still stop when idle.
    setInterval(async () => {
      if (busy || stopped || document.visibilityState !== "visible") return;
      try {
        const keep = lang;
        dash = await api("/api/state", undefined, true);
        lang = keep;
        render();
      } catch {}
    }, 60_000);
  }
  start();
})();
