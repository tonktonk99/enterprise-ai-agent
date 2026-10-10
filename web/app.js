const taskInput = document.getElementById("task-input");
const runBtn = document.getElementById("run-button");
const chatMessages = document.getElementById("chat-messages");
const welcomeScreen = document.getElementById("welcome-screen");
const historyList = document.getElementById("history-list");
const errorBanner = document.getElementById("error-banner");
const newChatBtn = document.getElementById("new-chat-btn");

let activeRunId = null;
let pollTimer = null;

// Helpers
function createElement(tag, className, textContent) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (textContent) el.textContent = textContent;
  return el;
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

function showError(msg) {
  errorBanner.textContent = msg;
  errorBanner.hidden = false;
  setTimeout(() => errorBanner.hidden = true, 5000);
}

// Setup input
taskInput.addEventListener("input", () => {
  taskInput.style.height = "auto";
  taskInput.style.height = Math.min(taskInput.scrollHeight, 200) + "px";
  runBtn.disabled = taskInput.value.trim().length === 0;
});
taskInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    if (!runBtn.disabled) runBtn.click();
  }
});

// Setup suggestions
document.querySelectorAll(".suggestion-card").forEach(card => {
  card.addEventListener("click", () => {
    taskInput.value = card.dataset.prompt;
    taskInput.dispatchEvent(new Event("input"));
    runBtn.click();
  });
});

newChatBtn.addEventListener("click", () => {
  activeRunId = null;
  clearTimeout(pollTimer);
  chatMessages.innerHTML = "";
  chatMessages.appendChild(welcomeScreen);
  welcomeScreen.style.display = "flex";
  taskInput.value = "";
  taskInput.dispatchEvent(new Event("input"));
  document.querySelectorAll(".history-item").forEach(i => i.classList.remove("active"));
});

// Chat Logic
runBtn.addEventListener("click", async () => {
  const prompt = taskInput.value.trim();
  if (!prompt) return;

  welcomeScreen.style.display = "none";
  taskInput.value = "";
  taskInput.dispatchEvent(new Event("input"));
  
  // Add User message
  const userMsg = createElement("div", "message message-user");
  const userContent = createElement("div", "message-content", prompt);
  userMsg.appendChild(userContent);
  chatMessages.appendChild(userMsg);
  
  // Create AI placeholder
  const aiMsg = createElement("div", "message message-ai");
  const avatar = createElement("div", "message-avatar", "F");
  const aiContent = createElement("div", "message-content");
  aiContent.id = "active-ai-response";
  aiMsg.appendChild(avatar);
  aiMsg.appendChild(aiContent);
  chatMessages.appendChild(aiMsg);
  
  chatMessages.scrollTop = chatMessages.scrollHeight;
  runBtn.disabled = true;
  taskInput.disabled = true;

  try {
    const res = await api("/api/runs", { task: prompt });
    activeRunId = res.id;
    pollRun();
    refreshHistory();
  } catch(e) {
    aiContent.textContent = "Error: " + e.message;
    runBtn.disabled = false;
    taskInput.disabled = false;
  }
});

async function pollRun() {
  if (!activeRunId) return;
  try {
    const run = await api(`/api/runs/${activeRunId}`);
    renderRunUI(run);
    
    if (run.status === "queued" || run.status === "running") {
      pollTimer = setTimeout(pollRun, 1000);
    } else {
      runBtn.disabled = false;
      taskInput.disabled = false;
      taskInput.focus();
    }
  } catch(e) {
    showError(e.message);
    runBtn.disabled = false;
    taskInput.disabled = false;
  }
}

function renderRunUI(run) {
  let container = document.getElementById(`run-ui-${run.id}`);
  if (!container) {
    container = document.getElementById("active-ai-response");
    if (container) {
      container.id = `run-ui-${run.id}`;
      container.innerHTML = "";
    } else {
      return; // Not in view
    }
  }

  // Card Structure
  container.innerHTML = "";
  const card = createElement("div", "run-card");
  
  // Header
  const header = createElement("div", "run-header");
  header.appendChild(createElement("span", "", `Forge AI กำลังทำงาน...`));
  const badge = createElement("span", `run-status-badge ${run.status}`, run.status);
  header.appendChild(badge);
  card.appendChild(header);

  // Tracker
  const tracker = createElement("div", "pipeline-tracker");
  run.stages.forEach(stage => {
    const st = createElement("div", `tracker-stage ${stage.status}`);
    st.appendChild(createElement("div", "stage-dot"));
    st.appendChild(createElement("span", "stage-name", stage.name));
    tracker.appendChild(st);
  });
  card.appendChild(tracker);

  // Details if done
  if (run.status === "awaiting_approval" || run.status === "applied" || run.status === "rejected") {
    if (run.status === "awaiting_approval") {
      header.firstChild.textContent = "รอการอนุมัติเพื่อนำไปใช้";
    } else if (run.status === "applied") {
      header.firstChild.textContent = "นำไปใช้เรียบร้อยแล้ว";
    } else {
      header.firstChild.textContent = "ถูกปฏิเสธ";
    }

    const details = createElement("div", "run-details");
    
    // Plan
    if (run.plan) {
      details.appendChild(createElement("strong", "", "แผนการทำงาน:"));
      details.appendChild(createElement("p", "", run.plan.goal));
    }
    
    // Diff
    if (run.diff) {
      details.appendChild(createElement("strong", "", "การเปลี่ยนแปลงไฟล์:"));
      const pre = createElement("pre", "diff-code");
      run.diff.split("\n").forEach(line => {
        const span = document.createElement("span");
        span.textContent = line + "\n";
        if (line.startsWith("+") && !line.startsWith("+++")) span.className = "diff-add";
        else if (line.startsWith("-") && !line.startsWith("---")) span.className = "diff-remove";
        pre.appendChild(span);
      });
      details.appendChild(pre);
    }
    
    // Security Findings
    if (run.findings && run.findings.length > 0) {
       details.appendChild(createElement("strong", "", "ประเด็นความปลอดภัย:"));
       const ul = createElement("ul");
       run.findings.forEach(f => ul.appendChild(createElement("li", "", `${f.severity.toUpperCase()}: ${f.message}`)));
       details.appendChild(ul);
    }

    card.appendChild(details);

    // Approve Bar
    if (run.status === "awaiting_approval") {
      const actions = createElement("div", "approve-actions");
      const label = createElement("label");
      const cb = createElement("input");
      cb.type = "checkbox";
      label.appendChild(cb);
      label.appendChild(document.createTextNode(" ฉันตรวจโค้ดแล้ว"));
      actions.appendChild(label);
      
      const rejectBtn = createElement("button", "reject-btn", "ปฏิเสธ");
      const applyBtn = createElement("button", "approve-btn", "นำไปใช้");
      applyBtn.disabled = true;
      cb.addEventListener("change", () => applyBtn.disabled = !cb.checked);
      
      rejectBtn.onclick = async () => {
         rejectBtn.disabled = true;
         await api(`/api/runs/${run.id}/reject`);
         pollRun();
      };
      applyBtn.onclick = async () => {
         applyBtn.disabled = true;
         await api(`/api/runs/${run.id}/apply`, { approved: true });
         pollRun();
      };
      
      actions.appendChild(rejectBtn);
      actions.appendChild(applyBtn);
      card.appendChild(actions);
    }
  }

  container.appendChild(card);
  if (run.status === "running") chatMessages.scrollTop = chatMessages.scrollHeight;
}

// History
async function refreshHistory() {
  try {
    const res = await api("/api/runs", null, "GET");
    historyList.innerHTML = "";
    if (res.runs.length === 0) {
      historyList.appendChild(createElement("li", "empty-history", "ยังไม่มีประวัติ"));
      return;
    }
    res.runs.forEach(r => {
      const li = createElement("li", "history-item", r.task.substring(0, 30) + "...");
      if (r.id === activeRunId) li.classList.add("active");
      li.onclick = () => loadHistoryRun(r.id, r.task);
      historyList.appendChild(li);
    });
  } catch(e) {}
}

function loadHistoryRun(id, task) {
  activeRunId = id;
  welcomeScreen.style.display = "none";
  chatMessages.innerHTML = "";
  
  const userMsg = createElement("div", "message message-user");
  userMsg.appendChild(createElement("div", "message-content", task));
  chatMessages.appendChild(userMsg);
  
  const aiMsg = createElement("div", "message message-ai");
  aiMsg.appendChild(createElement("div", "message-avatar", "F"));
  const aiContent = createElement("div", "message-content");
  aiContent.id = `run-ui-${id}`;
  aiMsg.appendChild(aiContent);
  chatMessages.appendChild(aiMsg);
  
  document.querySelectorAll(".history-item").forEach(i => i.classList.remove("active"));
  refreshHistory(); // update active state
  pollRun();
}

// Health check
fetch("/api/health")
  .then(res => res.json())
  .then(h => {
    document.getElementById("workspace-name").textContent = h.workspace;
    document.getElementById("provider-status").textContent = h.local_model_ready ? `Local Model: ${h.model}` : "Model not ready";
  })
  .catch(() => document.getElementById("provider-status").textContent = "Offline");

refreshHistory();

// Org Data Modal
const modal = document.getElementById("org-data-modal");
document.getElementById("org-data-btn").onclick = () => modal.showModal();
document.getElementById("close-modal").onclick = () => modal.close();

const importBtn = document.getElementById("import-btn");
const clearBtn = document.getElementById("clear-data-btn");
const askBtn = document.getElementById("ask-btn");
const csvInput = document.getElementById("csv-input");

importBtn.onclick = () => csvInput.click();
csvInput.onchange = async () => {
  const file = csvInput.files[0];
  if (!file) return;
  importBtn.textContent = "Loading...";
  try {
    const res = await api("/api/data/import", { filename: file.name, content: await file.text() });
    document.getElementById("dataset-status").textContent = `Loaded ${res.record_count} records`;
    document.getElementById("org-question").disabled = false;
    askBtn.disabled = false;
    clearBtn.hidden = false;
  } catch(e) { alert(e.message); }
  importBtn.textContent = "เลือกไฟล์ CSV";
};

clearBtn.onclick = async () => {
  if (confirm("ลบข้อมูล?")) {
    await api("/api/data/clear", { approved: true });
    document.getElementById("dataset-status").textContent = "ยังไม่มีชุดข้อมูล";
    document.getElementById("org-question").disabled = true;
    askBtn.disabled = true;
    clearBtn.hidden = true;
  }
};

askBtn.onclick = async () => {
  const q = document.getElementById("org-question").value;
  if (!q) return;
  askBtn.disabled = true;
  try {
    const res = await api("/api/ask", { question: q });
    document.getElementById("qa-answer").hidden = false;
    document.getElementById("answer-text").textContent = res.answer;
  } catch(e) { alert(e.message); }
  askBtn.disabled = false;
};
