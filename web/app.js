const taskInput = document.querySelector("#task-input");
const runButton = document.querySelector("#run-button");
const applyButton = document.querySelector("#apply-button");
const errorBanner = document.querySelector("#error-banner");
const resultSection = document.querySelector("#result-section");
const characterCount = document.querySelector("#character-count");
const appShell = document.querySelector(".app-shell");
const csvInput = document.querySelector("#csv-input");
const importButton = document.querySelector("#import-button");
const clearDataButton = document.querySelector("#clear-data-button");
const orgQuestion = document.querySelector("#org-question");
const askButton = document.querySelector("#ask-button");
const qaAnswer = document.querySelector("#qa-answer");
let activeProposal = null;

function addText(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

function setBusy(isBusy) {
  appShell.classList.toggle("is-thinking", isBusy);
  runButton.disabled = isBusy;
  runButton.setAttribute("aria-busy", String(isBusy));
  runButton.innerHTML = isBusy
    ? '<span class="button-spark">✳</span><span>Forge กำลังวางแผนและตรวจโค้ด…</span>'
    : '<span class="button-spark">✳</span><span>ให้ Forge เริ่มทำงาน</span><span class="button-arrow">→</span>';
}

async function api(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
  return result;
}

function displayError(message) {
  const messages = {
    "Task must contain 1 to 3000 characters.": "พิมพ์รายละเอียดงานก่อนเริ่มได้เลย (ไม่เกิน 3,000 ตัวอักษร)",
    "Only localhost requests are allowed.": "อนุญาตเฉพาะการใช้งานจากเครื่องนี้เท่านั้น",
  };
  if (message.startsWith("Session required.")) {
    return "ยังไม่ได้เข้าสู่เซสชัน กรุณาเปิดลิงก์ Forge ที่มี ?token= จากหน้าต่าง Terminal ที่รันเซิร์ฟเวอร์";
  }
  if (message.startsWith("Could not reach the local model.")) {
    return "เชื่อมต่อโมเดลในเครื่องไม่ได้ กรุณาเปิด Ollama และติดตั้งโมเดลที่ตั้งค่าไว้";
  }
  if (message.startsWith("Import an approved CSV dataset")) {
    return "กรุณานำเข้าไฟล์ CSV ที่ได้รับอนุญาตก่อนถาม";
  }
  return messages[message] || message;
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
    const response = await fetch("/api/data/status");
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || "อ่านสถานะข้อมูลไม่ได้");
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
      return;
    }
    datasetStatus.textContent = `พร้อมค้นหา · ${status.record_count.toLocaleString()} รายการ`;
    datasetDetail.textContent = `อัปเดต ${new Date(status.imported_at).toLocaleString("th-TH")}`;
    allowedFields.textContent = `คอลัมน์ในชุดข้อมูล: ${status.headers.join(" · ")}`;
    allowedFields.hidden = false;
    clearDataButton.hidden = false;
    orgQuestion.disabled = false;
    askButton.disabled = false;
  } catch (error) {
    showError(error.message);
  }
}

function renderList(id, values, emptyText) {
  const list = document.querySelector(id);
  list.replaceChildren();
  if (!values.length) {
    addText(list, "li", emptyText, "empty-message");
    return;
  }
  values.forEach((value) => addText(list, "li", value));
}

function renderProposal(proposal) {
  activeProposal = proposal;
  resultSection.hidden = false;
  document.querySelector("#result-summary").textContent = proposal.summary;
  document.querySelector("#proposal-status").textContent =
    proposal.status === "ready" ? "รอตรวจสอบ" : "ถูกระงับ · มีประเด็นให้ตรวจ";
  document.querySelector("#proposal-status").className =
    `proposal-status${proposal.status === "ready" ? "" : " blocked"}`;
  renderList("#plan-list", proposal.plan, "ยังไม่มีรายละเอียดแผน");

  const securityList = document.querySelector("#security-list");
  securityList.replaceChildren();
  if (!proposal.security_findings.length) {
    addText(securityList, "div", "ไม่พบประเด็นจากการตรวจเบื้องต้น", "security-item low");
  } else {
    proposal.security_findings.forEach((finding) => {
      addText(securityList, "div", `${finding.severity.toUpperCase()} · ${finding.path || "review"} — ${finding.message}`, `security-item ${finding.severity}`);
    });
  }
  const context = proposal.context;
  document.querySelector("#context-stats").textContent =
    `Context: ${context.files_included}/${context.files_scanned} files · ${context.context_chars.toLocaleString()} characters · ${context.files_skipped_for_secrets} secret-screened`;

  const fileList = document.querySelector("#file-list");
  fileList.replaceChildren();
  document.querySelector("#file-count").textContent =
    `เสนอ ${proposal.files.length} ไฟล์ · ตรวจเนื้อหาได้ก่อนอนุมัติ`;
  proposal.files.forEach((file) => {
    const card = document.createElement("div");
    card.className = "file-card";
    const head = document.createElement("div");
    head.className = "file-head";
    addText(head, "span", "▤");
    addText(head, "strong", file.path);
    addText(head, "span", file.reason || "เสนอการเปลี่ยนแปลง", "file-reason");
    const copyButton = addText(head, "button", "คัดลอก", "copy-button");
    copyButton.type = "button";
    copyButton.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(file.content);
        copyButton.textContent = "คัดลอกแล้ว";
        window.setTimeout(() => { copyButton.textContent = "คัดลอก"; }, 1500);
      } catch {
        showError("คัดลอกไม่ได้ กรุณาเลือกและคัดลอกจากกล่องโค้ดแทน");
      }
    });
    const editor = document.createElement("textarea");
    editor.className = "file-content";
    editor.setAttribute("aria-label", `Review proposed contents for ${file.path}`);
    editor.spellcheck = false;
    editor.value = file.content;
    editor.readOnly = true;
    card.append(head, editor);
    fileList.append(card);
  });
  renderList("#tests-list", proposal.tests, "ยังไม่มีข้อเสนอการทดสอบ");
  renderList("#deploy-list", proposal.deployment_notes, "ไม่มีการ deploy อัตโนมัติ");
  applyButton.disabled = proposal.status !== "ready" || !proposal.files.length;
  applyButton.innerHTML = 'อนุมัติและนำไปใช้ <span>→</span>';
  resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
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
    const result = await api("/api/data/import", {
      filename: file.name,
      content: await file.text(),
    });
    clearAnswer();
    orgQuestion.value = "";
    document.querySelector("#dataset-status").textContent =
      `พร้อมค้นหา · ${result.record_count.toLocaleString()} รายการ`;
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
  if (!orgQuestion.value.trim()) {
    showError("พิมพ์คำถามเกี่ยวกับข้อมูลที่นำเข้าก่อนครับ");
    orgQuestion.focus();
    return;
  }
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

runButton.addEventListener("click", async () => {
  if (!taskInput.value.trim()) {
    showError("พิมพ์รายละเอียดงานก่อนเริ่มได้เลย (ไม่เกิน 3,000 ตัวอักษร)");
    taskInput.focus();
    return;
  }
  errorBanner.hidden = true;
  resultSection.hidden = true;
  setBusy(true);
  try {
    renderProposal(await api("/api/tasks", { task: taskInput.value }));
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
});

applyButton.addEventListener("click", async () => {
  if (!activeProposal || applyButton.disabled) return;
  if (!window.confirm("ยืนยันนำไฟล์ที่ตรวจแล้วไปเขียนใน workspace นี้หรือไม่?")) return;
  errorBanner.hidden = true;
  applyButton.disabled = true;
  applyButton.textContent = "Applying…";
  try {
    await api(`/api/tasks/${encodeURIComponent(activeProposal.id)}/apply`, {
      approved: true,
    });
    activeProposal.status = "applied";
    document.querySelector("#proposal-status").textContent = "นำไปใช้แล้ว";
    applyButton.textContent = "นำการเปลี่ยนแปลงไปใช้แล้ว";
    applyButton.disabled = true;
  } catch (error) {
    showError(error.message);
    applyButton.disabled = false;
    applyButton.innerHTML = 'อนุมัติและนำไปใช้ <span>→</span>';
  }
});

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
