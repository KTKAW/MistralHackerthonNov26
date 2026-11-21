/* le-chonk sandbox audit console — vanilla JS, no build step. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = { runs: [], timer: null, detail: null, es: null };

/* ---------- tabs ---------- */
document.querySelectorAll("#tabs .tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#tabs .tab").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tabpage").forEach((p) =>
      p.classList.toggle("active", p.id === "tab-" + btn.dataset.tab));
    if (btn.dataset.tab === "runs") startPolling(); else stopPolling();
  });
});

/* ---------- health ---------- */
async function health() {
  try {
    const h = await (await fetch("/api/health")).json();
    $("#health").textContent = "runs: " + h.runs_root;
  } catch { $("#health").textContent = "server unreachable"; }
}

/* ---------- runs grid ---------- */
function startPolling() {
  fetchRuns();
  if (!state.timer) state.timer = setInterval(fetchRuns, 2000);
}
function stopPolling() { clearInterval(state.timer); state.timer = null; }

async function fetchRuns() {
  try {
    const data = await (await fetch("/api/runs")).json();
    state.runs = data.runs;
    renderCards();
    $("#runs-meta").textContent = data.runs.length + " run(s) · polling 2 s";
  } catch { /* server down */ }
}

function verdictBadge(v) {
  if (!v) return '<span class="badge gray">no verdict</span>';
  const color = { not_affected: "green", affected_proven: "red",
    affected_fixed: "amber", needs_human: "purple" }[v] || "gray";
  return `<span class="badge ${color}">${esc(v)}</span>`;
}

function renderCards() {
  const box = $("#cards");
  box.innerHTML = "";
  for (const r of state.runs) {
    const douane = r.douane_pct == null ? '<span class="chip">no shell calls</span>'
      : `<span class="chip ${r.douane_pct === 100 ? "ok" : "bad"}">douane ${r.douane_pct}%</span>`;
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `
      <h3>${esc(r.run_id)} / ${esc(r.repo)}</h3>
      <div class="row">${verdictBadge(r.verdict)}
        <span class="chip">${esc(r.status)}</span>${douane}
        ${r.deny_count ? `<span class="chip bad">${r.deny_count} denied</span>` : ""}</div>
      <div class="row dim mono" style="font-size:11px">
        ${r.tokens != null ? esc(r.tokens) + " tok · " : ""}
        ${r.cost_usd != null ? "$" + Number(r.cost_usd).toFixed(4) : ""}
      </div>`;
    card.addEventListener("click", () => openRun(r.run_id, r.repo));
    box.appendChild(card);
  }
  if (!state.runs.length) box.innerHTML = '<p class="dim">no runs yet under runs/</p>';
}

/* ---------- run detail (shell; sections filled in later steps) ---------- */
async function openRun(run_id, repo) {
  $("#runs-view").classList.add("hidden");
  $("#detail-view").classList.remove("hidden");
  const d = await (await fetch(`/api/runs/${encodeURIComponent(run_id)}/${encodeURIComponent(repo)}`)).json();
  state.detail = d;
  renderDetail();
}

function renderDetail() {
  const d = state.detail;
  if (!d) return;
  const c = d.card, v = d.verdict || {};
  const stages = Object.entries(d.stages).map(([k, ok]) =>
    `<span class="stage ${ok ? "done" : "missing"}">${k}</span>`).join('<span class="stage-arrow">→</span>');
  $("#detail").innerHTML = `
    <h2>${esc(d.run_id)} / ${esc(d.repo)} ${verdictBadge(v.verdict)}
      <span class="chip">${esc(c.status)}</span></h2>
    <div class="pipeline">${stages}</div>
    <div class="panel"><h3>Summary</h3><div class="kv">
      <div><b>reason</b> ${esc(v.reason || "—")}</div>
      <div><b>cost</b> ${c.cost_usd != null ? "$" + Number(c.cost_usd).toFixed(4) : "—"}
           · <b>tokens</b> ${c.tokens ?? "—"} · <b>outcome</b> ${esc(c.outcome || "—")}</div>
      <div><b>douane coverage</b> ${c.douane_pct == null ? "—" : c.douane_pct + "%"}
           (${c.shell_calls} shell calls, ${c.deny_count} denied)</div>
    </div></div>
    <div id="detail-sections"></div>`;
  renderVerdictPanel(d);
  renderGitPanel(d);
  renderHookPanel(d);
  startHookStream(d.run_id, d.repo);
}

/* ---------- verdict panel: path chain, proof, suite, fix ---------- */
function renderVerdictPanel(d) {
  const v = d.verdict;
  const host = $("#detail-sections");
  const panel = document.createElement("div");
  panel.className = "panel";
  if (!v) { panel.innerHTML = "<h3>Verdict</h3><p class='dim'>no verdict.json yet</p>"; host.appendChild(panel); return; }

  const chain = (v.path || []).map((p) => `
    <li><a href="#" class="file-link" data-path="${esc(p.file)}" data-line="${p.line}">
        ${esc(p.file)}:${p.line}</a>
      <span class="note">${esc(p.note)}</span></li>`).join("");

  const proof = (v.proof || []).map((t) => `<li class="mono">${esc(t)}</li>`).join("")
    || '<li class="dim">none</li>';
  const follow = (v.follow_ups || []).map((t) => `<li>${esc(t)}</li>`).join("")
    || '<li class="dim">none</li>';
  const fix = v.fix ? `${esc(v.fix.kind)} → ${esc(v.fix.target || "")}
    ${v.fix.diff_file ? "(" + esc(v.fix.diff_file) + ")" : ""}` : "—";

  const bars = suiteBars(v.suite);
  panel.innerHTML = `
    <h3>Verdict — ${verdictBadge(v.verdict)}</h3>
    <div class="kv"><div><b>advisory</b> ${esc((v.advisory || {}).id || "")} ·
      ${esc((v.advisory || {}).package || "")} ${esc((v.advisory || {}).affected_range || "")} ·
      <span class="mono">${esc((v.advisory || {}).flawed_function || "")}</span></div>
    <div><b>fix</b> ${fix}</div></div>
    <h3>Reachability path (entry point → flawed function)</h3>
    <ul class="path-chain">${chain || '<li class="dim">no path recorded</li>'}</ul>
    <h3>Proof tests (must fail before fix, pass after)</h3>
    <ul class="tight">${proof}</ul>
    <h3>Suite before → after</h3>${bars}
    <h3>Follow-ups</h3>
    <ul class="tight">${follow}</ul>`;
  host.appendChild(panel);
  panel.querySelectorAll("a.file-link").forEach((a) =>
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openFile(d.run_id, d.repo, a.dataset.path, Number(a.dataset.line) || 0);
    }));
}

function suiteBars(suite) {
  if (!suite || !suite.before || !suite.after) return '<span class="dim">—</span>';
  const g = (c, label) => {
    const p = c.passed || 0, f = c.failed || 0, max = Math.max(p, f, 1);
    return `<div class="bar-group">${label}<br>
      <span class="bar pass" style="height:${Math.max(2, 50 * p / max)}px"></span><span class="bar fail" style="height:${Math.max(f ? 2 : 0, 50 * f / max)}px"></span><br>
      ${p}✓ ${f}✗</div>`;
  };
  return `<div class="bars">${g(suite.before, "before")}${g(suite.after, "after")}</div>`;
}

/* ---------- git panel: work-copy changes vs baseline ---------- */
async function renderGitPanel(d) {
  const host = $("#detail-sections");
  const panel = document.createElement("div");
  panel.className = "panel";
  panel.innerHTML = "<h3>Work-copy changes (git vs baseline)</h3><p class='dim'>loading…</p>";
  host.appendChild(panel);
  try {
    const g = await (await fetch(`/api/runs/${encodeURIComponent(d.run_id)}/${encodeURIComponent(d.repo)}/diff`)).json();
    if (!g.available) { panel.innerHTML = "<h3>Work-copy changes</h3><p class='dim'>no git baseline</p>"; return; }
    const rows = g.entries.map((e) =>
      `<li class="mono" style="color:${e.code.includes("D") ? "var(--red)" : "inherit"}">${esc(e.code)} ${esc(e.path)}</li>`).join("");
    panel.innerHTML = `
      <h3>Work-copy changes (git vs baseline)</h3>
      ${g.deleted.length ? `<p style="color:var(--red)">⚠ deleted files (rule: never delete/weaken a test): ${g.deleted.map(esc).join(", ")}</p>` : ""}
      <ul class="tight">${rows || '<li class="dim">clean — no changes</li>'}</ul>
      ${g.diff ? `<details><summary>diff</summary><pre class="out">${esc(g.diff)}</pre></details>` : ""}`;
  } catch { panel.innerHTML = "<h3>Work-copy changes</h3><p class='dim'>failed to load</p>"; }
}

/* ---------- hook audit panel ---------- */
function renderHookPanel(d) {
  const host = $("#detail-sections");
  const panel = document.createElement("div");
  panel.className = "panel";
  panel.innerHTML = `<h3>Hook audit — live tail of hook.log
    <span class="chip" id="hook-live">connecting…</span></h3>
    <table class="audit"><thead><tr>
      <th>event</th><th>hook</th><th>command / path</th><th>detail</th>
    </tr></thead><tbody id="hook-rows"></tbody></table>`;
  host.appendChild(panel);
}

/* ---------- file viewer modal (confined server-side) ---------- */
async function openFile(run_id, repo, path, line) {
  const modal = $("#file-modal");
  modal.classList.remove("hidden");
  $("#file-title").textContent = path + (line ? ":" + line : "");
  $("#file-content").textContent = "loading…";
  try {
    const r = await fetch(`/api/runs/${encodeURIComponent(run_id)}/${encodeURIComponent(repo)}/file?path=${encodeURIComponent(path)}`);
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      $("#file-content").innerHTML = `<span class="err">${esc(e.detail || r.statusText)}</span>`;
      return;
    }
    const f = await r.json();
    const lines = f.content.split("\n");
    $("#file-content").innerHTML = lines.map((l, i) => {
      const n = i + 1;
      const hl = n === line ? ' style="background:rgba(88,166,255,.25)"' : "";
      return `<div${hl}><span class="dim" style="display:inline-block;width:3.5em;text-align:right;margin-right:1em">${n}</span>${esc(l)}</div>`;
    }).join("") + (f.truncated ? '\n<span class="err">…truncated</span>' : "");
    if (line) {
      const el = $("#file-content").children[line - 1];
      if (el && el.scrollIntoView) el.scrollIntoView({ block: "center" });
    }
  } catch { $("#file-content").textContent = "request failed"; }
}
$("#btn-close-file").addEventListener("click", () => $("#file-modal").classList.add("hidden"));

/* ---------- live hook audit (SSE) ---------- */
function startHookStream(run_id, repo) {
  closeHookStream();
  const url = `/api/runs/${encodeURIComponent(run_id)}/${encodeURIComponent(repo)}/hooklog`;
  state.es = new EventSource(url);
  state.es.onopen = () => { const el = $("#hook-live"); if (el) { el.textContent = "live"; el.className = "chip ok"; } };
  state.es.onerror = () => { const el = $("#hook-live"); if (el) { el.textContent = "reconnecting…"; el.className = "chip bad"; } };
  state.es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    addAuditRow(ev);
  };
}
function closeHookStream() { if (state.es) { state.es.close(); state.es = null; } }

function addAuditRow(ev) {
  const tbody = $("#hook-rows");
  if (!tbody) return;
  const tr = document.createElement("tr");
  tr.className = ev.event === "deny" ? "deny" : ev.event === "rewrite" ? "rewrite" : "";
  let cmd = "", detail = "";
  if (ev.event === "rewrite") {
    cmd = `<span class="mono">${esc(ev.rewritten)}</span>
           <span class="orig">was: ${esc(ev.original)}</span>`;
    detail = esc(ev.tool || "");
  } else if (ev.path) {
    cmd = `<span class="mono">${esc(ev.path)}</span>`;
    detail = esc(ev.tool || "");
  } else {
    cmd = `<span class="mono">${esc(ev.original || ev.command || "")}</span>`;
    detail = esc(ev.reason || ev.detail || "");
  }
  tr.innerHTML = `<td>${esc(ev.event)}</td><td>${esc(ev.hook || "")}</td><td class="cmd">${cmd}</td><td>${detail}</td>`;
  tbody.prepend(tr);
  while (tbody.rows.length > 500) tbody.deleteRow(-1);
}

$("#btn-back").addEventListener("click", () => {
  $("#detail-view").classList.add("hidden");
  $("#runs-view").classList.remove("hidden");
  closeHookStream();
  state.detail = null;
});

health();
startPolling();
