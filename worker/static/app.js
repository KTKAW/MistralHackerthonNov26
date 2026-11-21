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
}

$("#btn-back").addEventListener("click", () => {
  $("#detail-view").classList.add("hidden");
  $("#runs-view").classList.remove("hidden");
  state.detail = null;
});

health();
startPolling();
