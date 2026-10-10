const taskInput = document.querySelector("#task-input");
const runButton = document.querySelector("#run-button");
const characterCount = document.querySelector("#character-count");
const errorBanner = document.querySelector("#error-banner");
const appShell = document.querySelector(".app-shell");

const csvInput = document.querySelector("#csv-input");
const importButton = document.querySelector("#import-button");
const clearDataButton = document.querySelector("#clear-data-button");
const orgQuestion = document.querySelector("#org-question");
const askButton = document.querySelector("#ask-button");
const qaAnswer = document.querySelector("#qa-answer");

const runSection = document.querySelector("#run-section");
const runIdEl = document.querySelector("#run-id");
const runTaskEl = document.querySelector("#run-task");
const runMetaEl = document.querySelector("#run-meta");
const runStatusEl = document.querySelector("#run-status");
const patchLink = document.querySelector("#patch-link");
const pipelineTracker = document.querySelector("#pipeline-tracker");
const runErrorEl = document.querySelector("#run-error");

const confirmDiff = document.querySelector("#confirm-diff");
const rejectBtn = document.querySelector("#reject-button");
const approveBtn = document.querySelector("#approve-button");
const approveStatus = document.querySelector("#approve-status");

let activeRunId = null;
let pollTimer = null;

function addText(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

async function api(path, payload = undefined, method = undefined) {
  const options = {
    method: method || (payload ? "POST" : "GET"),
    headers: { "Content-Type": "application/json" }
  };
  if (payload) options.body = JSON.stringify(payload);
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
  return result;
}

function displayError(message) {
  if (message.startsWith("Session required.")) return "ยังไม่ได้เข้าสู่เซสชัน กรุณาเปิดลิงก์ Forge ที่มี ?token= จากหน้าต่าง Terminal ที่รันเซิร์ฟเวอร์";
  if (message.startsWith("Could not reach the local model.")) return "เชื่อมต่อโมเดลในเครื่องไม่ได้ กรุณาเปิด Ollama และติดตั้งโมเดลที่ตั้งค่าไว้";
  if (message.startsWith("Import an approved CSV dataset")) return "กรุณานำเข้าไฟล์ CSV ที่ได้รับอนุญาตก่อนถาม";
  return message;
}

function showError(message) {
  errorBanner.textContent = displayError(message);
  errorBanner.hidden = false;
}

function clearAnswer() {
  qaAnswer.hidden = true;
  document.querySelector("#answer-text").textContent = "";
  document.querySelector("#answer-sources").replaceChildren();
}

async function refreshDataset() {
  try {
    const status = await api("/api/data/status");
    const datasetStatus = document.querySelector("#dataset-status");
    const datasetDetail = document.querySelector("#dataset-detail");
    const allowedFields = document.querySelector("#allowed-fields");
    if (!status.loaded) {
      datasetStatus.textContent = "ยังไม่มีชุดข้อมูล";
      datasetDetail.textContent = "เริ่มจากไฟล์ CSV ที่คุณมีสิทธิ์ใช้งาน";
      allowedFields.hidden = true;
      clearDataButton.hidden = true;
      orgQuestion.disabled = true;
      askButton.disabled = true;
      document.querySelector("#profile-panel").hidden = true;
      return;
    }
    datasetStatus.textContent = `พร้อมค้นหา · ${status.record_count.toLocaleString()} รายการ`;
    datasetDetail.textContent = `อัปเดต ${new Date(status.imported_at).toLocaleString("th-TH")}`;
    allowedFields.textContent = `คอลัมน์ในชุดข้อมูล: ${status.headers.join(" · ")}`;
    allowedFields.hidden = false;
    clearDataButton.hidden = false;
    orgQuestion.disabled = false;
    askButton.disabled = false;
    
    // Load profile
    loadProfile();
  } catch (error) {
    showError(error.message);
  }
}

async function loadProfile() {
  try {
    const profile = await api("/api/data/profile");
    if (profile.loaded) {
      document.querySelector("#profile-panel").hidden = false;
      const tbody = document.querySelector("#profile-body");
      tbody.replaceChildren();
      profile.columns.forEach(col => {
        const tr = document.createElement("tr");
        addText(tr, "td", col.name, "col-name");
        addText(tr, "td", col.non_empty.toLocaleString());
        addText(tr, "td", col.distinct.toLocaleString());
        const topStr = col.top.map(t => `${t.value} (${t.count})`).join(", ");
        addText(tr, "td", topStr);
        const numStr = col.numeric ? `${col.numeric.min} · ${col.numeric.max} · ${col.numeric.mean.toFixed(2)}` : "-";
        addText(tr, "td", numStr);
        tbody.append(tr);
      });
    }
  } catch(e) {}
}

taskInput.addEventListener("input", () => {
  characterCount.textContent = `${taskInput.value.length.toLocaleString()} / 3,000`;
});

document.querySelectorAll(".suggestion-chip").forEach((button) => {
  button.addEventListener("click", () => {
    taskInput.value = button.dataset.prompt;
    taskInput.dispatchEvent(new Event("input"));
    taskInput.focus();
  });
});

taskInput.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter" && !runButton.disabled) {
    runButton.click();
  }
});

importButton.addEventListener("click", () => csvInput.click());

csvInput.addEventListener("change", async () => {
  const file = csvInput.files?.[0];
  if (!file) return;
  errorBanner.hidden = true;
  if (!file.name.toLowerCase().endsWith(".csv") || file.size > 1_500_000) {
    showError("เลือกไฟล์ .csv ขนาดไม่เกิน 1.5 MB");
    csvInput.value = "";
    return;
  }
  importButton.disabled = true;
  importButton.textContent = "กำลังนำเข้าข้อมูล…";
  try {
    const result = await api("/api/data/import", { filename: file.name, content: await file.text() });
    clearAnswer();
    orgQuestion.value = "";
    await refreshDataset();
  } catch (error) {
    showError(error.message);
  } finally {
    importButton.disabled = false;
    importButton.textContent = "เลือกไฟล์ CSV";
    csvInput.value = "";
  }
});

clearDataButton.addEventListener("click", async () => {
  if (!window.confirm("ลบข้อมูล CSV ที่เก็บไว้ในเครื่องนี้ทั้งหมดหรือไม่?")) return;
  clearDataButton.disabled = true;
  try {
    await api("/api/data/clear", { approved: true });
    clearAnswer();
    orgQuestion.value = "";
    await refreshDataset();
  } catch (error) {
    showError(error.message);
  } finally {
    clearDataButton.disabled = false;
  }
});

askButton.addEventListener("click", async () => {
  if (!orgQuestion.value.trim()) return;
  errorBanner.hidden = true;
  askButton.disabled = true;
  appShell.classList.add("is-thinking");
  askButton.textContent = "กำลังค้นข้อมูลในเครื่อง…";
  try {
    const result = await api("/api/ask", { question: orgQuestion.value });
    document.querySelector("#answer-text").textContent = result.answer;
    document.querySelector("#answer-caveat").hidden = result.retrieval_complete;
    const sources = document.querySelector("#answer-sources");
    sources.replaceChildren();
    result.sources.forEach((source) => {
      addText(sources, "span", `${source.source_id} · CSV แถว ${source.csv_row}`, "source-chip");
    });
    qaAnswer.hidden = false;
  } catch (error) {
    showError(error.message);
  } finally {
    askButton.disabled = false;
    askButton.innerHTML = 'ถาม AI ภายใน <span>→</span>';
    appShell.classList.remove("is-thinking");
  }
});

orgQuestion.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter" && !askButton.disabled) {
    askButton.click();
  }
});

function setBusy(isBusy) {
  appShell.classList.toggle("is-thinking", isBusy);
  runButton.disabled = isBusy;
  taskInput.disabled = isBusy;
  runButton.innerHTML = isBusy
    ? '<span class="button-spark">✳</span><span>Forge กำลังทำงาน…</span>'
    : '<span class="button-spark">✳</span><span>เริ่ม Pipeline</span><span class="button-arrow">→</span>';
}

runButton.addEventListener("click", async () => {
  if (!taskInput.value.trim()) return;
  errorBanner.hidden = true;
  setBusy(true);
  try {
    const result = await api("/api/runs", { task: taskInput.value });
    activeRunId = result.id;
    startPolling();
  } catch (error) {
    showError(error.message);
    setBusy(false);
  }
});

function startPolling() {
  if (pollTimer) clearTimeout(pollTimer);
  runSection.hidden = false;
  runSection.scrollIntoView({ behavior: "smooth", block: "start" });
  pollRun();
}

async function pollRun() {
  try {
    const run = await api(`/api/runs/${activeRunId}`);
    renderRun(run);
    if (run.status === "queued" || run.status === "running") {
      pollTimer = setTimeout(pollRun, 1000);
    } else {
      setBusy(false);
      refreshMetrics();
      refreshHistory();
    }
  } catch (error) {
    runErrorEl.textContent = displayError(error.message);
    runErrorEl.hidden = false;
    setBusy(false);
  }
}

function renderRun(run) {
  runIdEl.textContent = run.id;
  runTaskEl.textContent = run.task;
  runStatusEl.textContent = run.status.toUpperCase();
  runStatusEl.className = `status-badge ${run.status}`;
  
  if (run.error) {
    runErrorEl.textContent = run.error;
    runErrorEl.hidden = false;
  } else {
    runErrorEl.hidden = true;
  }

  patchLink.hidden = (run.status !== "awaiting_approval" && run.status !== "applied");
  if (!patchLink.hidden) {
    patchLink.href = `/api/runs/${run.id}/patch`;
  }

  // Render tracker
  pipelineTracker.replaceChildren();
  run.stages.forEach((stage, idx) => {
    const li = document.createElement("li");
    li.className = `tracker-stage ${stage.status}`;
    const circle = addText(li, "span", (idx + 1).toString(), "stage-circle");
    const name = addText(li, "span", stage.name, "stage-name");
    const meta = document.createElement("div");
    meta.className = "stage-meta";
    if (stage.duration_ms) {
      addText(meta, "span", `${(stage.duration_ms / 1000).toFixed(1)}s`);
    }
    if (stage.tokens?.total) {
      addText(meta, "span", `${stage.tokens.total.toLocaleString()} t`);
    }
    li.append(meta);
    if (stage.summary) {
      const tooltip = addText(li, "div", stage.summary, "stage-tooltip");
    }
    pipelineTracker.append(li);
  });

  // Render tabs
  renderPlanTab(run);
  renderDiffTab(run);
  renderTestsTab(run);
  renderSecurityTab(run);
  renderComplianceTab(run);
  renderProvenanceTab(run);
  renderTokensTab(run);

  // Approve bar
  confirmDiff.disabled = (run.status !== "awaiting_approval");
  rejectBtn.disabled = (run.status !== "awaiting_approval");
  approveBtn.disabled = (run.status !== "awaiting_approval") || !confirmDiff.checked;
  
  if (run.status === "awaiting_approval") {
    approveStatus.textContent = "รอการอนุมัติ…";
  } else if (run.status === "applied") {
    approveStatus.textContent = "นำไปใช้แล้ว";
    confirmDiff.checked = false;
  } else if (run.status === "rejected") {
    approveStatus.textContent = "ปฏิเสธแล้ว";
  } else {
    approveStatus.textContent = `สถานะ: ${run.status}`;
  }
}

confirmDiff.addEventListener("change", () => {
  if (activeRunId) {
    approveBtn.disabled = !confirmDiff.checked;
  }
});

rejectBtn.addEventListener("click", async () => {
  if (!activeRunId) return;
  rejectBtn.disabled = true;
  try {
    const res = await api(`/api/runs/${activeRunId}/reject`, {});
    runStatusEl.textContent = "REJECTED";
    approveStatus.textContent = "ปฏิเสธแล้ว";
    rejectBtn.disabled = true;
    approveBtn.disabled = true;
    confirmDiff.disabled = true;
  } catch (err) {
    showError(err.message);
    rejectBtn.disabled = false;
  }
});

approveBtn.addEventListener("click", async () => {
  if (!activeRunId || !confirmDiff.checked) return;
  approveBtn.disabled = true;
  approveBtn.textContent = "Applying...";
  try {
    const res = await api(`/api/runs/${activeRunId}/apply`, { approved: true });
    runStatusEl.textContent = "APPLIED";
    approveStatus.textContent = "นำไปใช้แล้ว";
    approveBtn.textContent = "อนุมัติและนำไปใช้ →";
    rejectBtn.disabled = true;
    approveBtn.disabled = true;
    confirmDiff.disabled = true;
  } catch (err) {
    showError(err.message);
    approveBtn.textContent = "อนุมัติและนำไปใช้ →";
    approveBtn.disabled = false;
  }
});

function renderPlanTab(run) {
  if (!run.plan) {
    document.querySelector("#plan-empty").hidden = false;
    document.querySelector("#plan-body").hidden = true;
    return;
  }
  document.querySelector("#plan-empty").hidden = true;
  document.querySelector("#plan-body").hidden = false;
  document.querySelector("#plan-goal").textContent = run.plan.goal;
  document.querySelector("#plan-risk").textContent = run.plan.risk;
  document.querySelector("#plan-risk").className = `risk-badge ${run.plan.risk}`;
  
  const steps = document.querySelector("#plan-steps");
  steps.replaceChildren();
  run.plan.steps.forEach(s => addText(steps, "li", s));

  const accept = document.querySelector("#plan-acceptance");
  accept.replaceChildren();
  run.plan.acceptance.forEach(s => addText(accept, "li", s));

  const fread = document.querySelector("#plan-files-read");
  fread.replaceChildren();
  run.plan.files_to_read.forEach(s => addText(fread, "li", s));

  const fcreate = document.querySelector("#plan-files-create");
  fcreate.replaceChildren();
  run.plan.files_to_create.forEach(s => addText(fcreate, "li", s));

  const reviewBox = document.querySelector("#review-box");
  if (run.review) {
    reviewBox.hidden = false;
    document.querySelector("#review-status").textContent = run.review.status;
    const rnotes = document.querySelector("#review-notes");
    rnotes.replaceChildren();
    run.review.notes.forEach(s => addText(rnotes, "li", s));
  } else {
    reviewBox.hidden = true;
  }
}

function renderDiffTab(run) {
  const fileSum = document.querySelector("#file-summary");
  const diffView = document.querySelector("#diff-view");
  fileSum.replaceChildren();
  diffView.replaceChildren();

  if (!run.files || run.files.length === 0) {
    addText(fileSum, "li", "ไม่มีการเปลี่ยนแปลงไฟล์");
    return;
  }
  
  run.files.forEach(f => {
    const li = document.createElement("li");
    li.textContent = `${f.change.toUpperCase()}: ${f.path} (+${f.additions} -${f.deletions})`;
    fileSum.append(li);
  });

  if (run.diff) {
    const pre = document.createElement("pre");
    pre.className = "diff-code";
    // Basic diff syntax coloring
    const lines = run.diff.split('\n');
    lines.forEach(line => {
      const span = document.createElement("span");
      span.textContent = line + '\n';
      if (line.startsWith("+") && !line.startsWith("+++")) span.className = "diff-add";
      else if (line.startsWith("-") && !line.startsWith("---")) span.className = "diff-remove";
      else if (line.startsWith("@@")) span.className = "diff-chunk";
      pre.append(span);
    });
    diffView.append(pre);
  }
}

function renderTestsTab(run) {
  if (!run.tests) {
    document.querySelector("#tests-empty").hidden = false;
    document.querySelector("#tests-body").hidden = true;
    return;
  }
  document.querySelector("#tests-empty").hidden = true;
  document.querySelector("#tests-body").hidden = false;
  const dl = document.querySelector("#tests-summary");
  dl.replaceChildren();
  
  const addItem = (dt, dd) => {
    addText(dl, "dt", dt);
    addText(dl, "dd", dd);
  };
  addItem("Status", run.tests.status);
  addItem("Command", run.tests.command || "-");
  addItem("Isolation", run.tests.isolation || "-");
  addItem("Attempts", (run.tests.attempts || 0).toString());
  addItem("Duration", run.tests.duration_ms ? `${run.tests.duration_ms}ms` : "-");

  document.querySelector("#tests-output").textContent = run.tests.output_tail || "No output";
}

function renderSecurityTab(run) {
  const fList = document.querySelector("#findings-list");
  fList.replaceChildren();
  if (!run.findings || run.findings.length === 0) {
    addText(fList, "li", "ไม่พบประเด็นความปลอดภัย");
    return;
  }
  run.findings.forEach(f => {
    const li = document.createElement("li");
    li.className = `finding-item ${f.severity}`;
    const head = document.createElement("div");
    head.className = "finding-head";
    addText(head, "span", f.severity.toUpperCase(), `finding-sev ${f.severity}`);
    addText(head, "strong", f.rule);
    if (f.cwe) addText(head, "span", f.cwe, "finding-cwe");
    li.append(head);
    const loc = f.path ? `${f.path}${f.line ? ':'+f.line : ''}` : "Global";
    addText(li, "div", `${loc} — ${f.message}`, "finding-msg");
    fList.append(li);
  });
}

function renderComplianceTab(run) {
  const tbody = document.querySelector("#compliance-body");
  tbody.replaceChildren();
  if (!run.compliance || run.compliance.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = "ไม่มีข้อมูล compliance";
    tr.append(td);
    tbody.append(tr);
    return;
  }
  run.compliance.forEach(c => {
    const tr = document.createElement("tr");
    addText(tr, "td", c.control);
    addText(tr, "td", c.framework);
    addText(tr, "td", c.evidence);
    addText(tr, "td", c.status, `status-${c.status}`);
    tbody.append(tr);
  });
}

function renderProvenanceTab(run) {
  if (!run.deployment) {
    document.querySelector("#provenance-empty").hidden = false;
    document.querySelector("#provenance-body").hidden = true;
    return;
  }
  document.querySelector("#provenance-empty").hidden = true;
  document.querySelector("#provenance-body").hidden = false;
  
  const dl = document.querySelector("#provenance-hashes");
  dl.replaceChildren();
  addText(dl, "dt", "Manifest SHA256");
  addText(dl, "dd", run.deployment.manifest_sha256);
  addText(dl, "dt", "Signature");
  const sigDd = document.createElement("dd");
  sigDd.textContent = (run.deployment.signature || "").substring(0, 32) + "...";
  const btn = addText(sigDd, "button", "Copy", "ghost-button small");
  btn.onclick = () => navigator.clipboard.writeText(run.deployment.signature);
  dl.append(sigDd);

  const notes = document.querySelector("#deploy-notes");
  notes.replaceChildren();
  (run.deployment.notes || []).forEach(n => addText(notes, "li", n));

  const rollback = document.querySelector("#rollback-steps");
  rollback.replaceChildren();
  (run.deployment.rollback || []).forEach(n => addText(rollback, "li", n));
}

function renderTokensTab(run) {
  const grid = document.querySelector("#token-grid");
  grid.replaceChildren();
  if (!run.metrics) return;
  const m = run.metrics;
  const addItem = (label, val) => {
    const d = document.createElement("div");
    d.className = "kpi-card";
    addText(d, "h4", label);
    addText(d, "div", val, "kpi-value");
    grid.append(d);
  };
  addItem("Total Tokens", m.total_tokens?.toLocaleString() || "0");
  addItem("Prompt", m.prompt_tokens?.toLocaleString() || "0");
  addItem("Completion", m.completion_tokens?.toLocaleString() || "0");
  addItem("LLM Calls", m.llm_calls?.toLocaleString() || "0");
  addItem("Savings %", m.token_savings_pct ? `${m.token_savings_pct.toFixed(1)}%` : "0%");
  addItem("Cache Hits", m.cache_hits?.toLocaleString() || "0");
}

// Tabs Logic
const tabs = document.querySelectorAll(".run-tab");
const panels = document.querySelectorAll(".run-panel");

tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => {
      t.setAttribute("aria-selected", "false");
      t.tabIndex = -1;
    });
    panels.forEach(p => p.hidden = true);
    
    tab.setAttribute("aria-selected", "true");
    tab.tabIndex = 0;
    const panelId = tab.getAttribute("aria-controls");
    document.getElementById(panelId).hidden = false;
  });
});

async function refreshMetrics() {
  try {
    const res = await api("/api/metrics", null, "GET");
    const kpi = document.querySelector("#kpi-grid");
    kpi.replaceChildren();
    const addItem = (label, val) => {
      const d = document.createElement("div");
      d.className = "kpi-card";
      addText(d, "h4", label);
      addText(d, "div", val, "kpi-value");
      kpi.append(d);
    };
    addItem("Total Runs", res.runs_total?.toString() || "0");
    addItem("Total Tokens", res.total_tokens?.toLocaleString() || "0");
    addItem("Tokens Saved", res.tokens_saved_estimate?.toLocaleString() || "0");
    addItem("Cache Hit Rate", res.cache_hit_rate !== null ? `${(res.cache_hit_rate * 100).toFixed(1)}%` : "-");
    addItem("Test Pass Rate", res.test_pass_rate !== null ? `${(res.test_pass_rate * 100).toFixed(1)}%` : "-");

    const bars = document.querySelector("#severity-bars");
    bars.replaceChildren();
    if (res.findings_by_severity) {
      for (const [sev, count] of Object.entries(res.findings_by_severity)) {
        if (count > 0) {
          const b = document.createElement("div");
          b.className = `sev-bar ${sev}`;
          b.style.flex = count.toString();
          b.title = `${sev}: ${count}`;
          bars.append(b);
        }
      }
    }
  } catch(e) {}
}

async function refreshHistory() {
  try {
    const res = await api("/api/runs", null, "GET");
    const list = document.querySelector("#history-list");
    list.replaceChildren();
    res.runs.forEach(r => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = "#";
      a.className = "history-item";
      a.onclick = (e) => {
        e.preventDefault();
        activeRunId = r.id;
        startPolling();
      };
      addText(a, "strong", r.task.substring(0, 50) + (r.task.length > 50 ? "..." : ""));
      addText(a, "span", `${r.status} · ${new Date(r.created_at).toLocaleString("th-TH")} · ${r.total_tokens || 0} tokens`, "history-meta");
      li.append(a);
      list.append(li);
    });
  } catch(e) {}
}

document.querySelector("#metrics-refresh")?.addEventListener("click", refreshMetrics);
document.querySelector("#history-refresh")?.addEventListener("click", refreshHistory);

fetch("/api/health")
  .then(async (response) => {
    const health = await response.json();
    if (response.status === 401) {
      showError(health.error);
      throw new Error(health.error);
    }
    return health;
  })
  .then((health) => {
    document.querySelector("#workspace-name").textContent = health.workspace;
    const status = document.querySelector("#provider-status");
    status.textContent = health.local_model_ready
      ? `AI ภายในพร้อมใช้ · ${health.model}`
      : `เปิด Ollama เพื่อใช้ AI ภายใน · ${health.model}`;
    status.title = health.local_model_ready
      ? "โมเดลพร้อมใช้ภายในเครื่อง ไม่มีการเรียก AI ภายนอก"
      : "ไม่พบโมเดลใน Ollama ภายในเครื่อง";
    if (!health.local_model_ready) {
      status.style.color = "#9a762f";
      status.previousElementSibling.style.background = "#d4a74f";
    }
  })
  .catch(() => {
    document.querySelector("#provider-status").textContent = "เชื่อมต่อ Agent ไม่ได้";
    document.querySelector(".repo-pill-dot").style.background = "#c75a56";
  });

refreshDataset();
refreshMetrics();
refreshHistory();
