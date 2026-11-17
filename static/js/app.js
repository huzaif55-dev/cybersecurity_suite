// CyberShield Application JS

// 1. Copy to clipboard
function copyToClipboard(text, elementId = null) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (elementId) {
      const el = document.getElementById(elementId);
      if (el) {
        const originalHtml = el.innerHTML;
        el.innerHTML = '<i class="bi bi-check2"></i> Copied!';
        setTimeout(() => {
          el.innerHTML = originalHtml;
        }, 1800);
      }
    } else {
      alert("Copied to clipboard!");
    }
  }).catch(err => {
    console.error("Clipboard copy failed: ", err);
  });
}

// 2. Toggle password visibility
function togglePasswordVisibility(fieldId, iconId) {
  const field = document.getElementById(fieldId);
  const icon = document.getElementById(iconId);
  if (!field || !icon) return;

  if (field.type === "password") {
    field.type = "text";
    icon.classList.remove("bi-eye");
    icon.classList.add("bi-eye-slash");
  } else {
    field.type = "password";
    icon.classList.remove("bi-eye-slash");
    icon.classList.add("bi-eye");
  }
}

// 3. Password Analyzer (Real-time)
let analyzeDebounceTimer = null;
function liveAnalyzePassword(password) {
  clearTimeout(analyzeDebounceTimer);
  analyzeDebounceTimer = setTimeout(() => {
    fetch("/api/passwords/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password })
    })
    .then(r => r.json())
    .then(data => {
      updatePasswordUI(data);
    })
    .catch(err => console.error("Error analyzing password:", err));
  }, 150);
}

function updatePasswordUI(data) {
  const scoreBar = document.getElementById("pwd-score-bar");
  const scoreLabel = document.getElementById("pwd-strength-label");
  const entropyVal = document.getElementById("pwd-entropy-val");
  const crackTimeVal = document.getElementById("pwd-crack-time");
  const tipsContainer = document.getElementById("pwd-tips-container");
  const criteriaContainer = document.getElementById("pwd-criteria-container");

  if (scoreBar) {
    scoreBar.style.width = data.score + "%";
    scoreBar.className = "progress-bar bg-" + data.strength_class;
  }
  if (scoreLabel) {
    scoreLabel.textContent = `${data.strength} (${data.score}/100)`;
    scoreLabel.className = "badge bg-" + data.strength_class;
  }
  if (entropyVal) {
    entropyVal.textContent = data.entropy_bits + " bits";
  }
  if (crackTimeVal) {
    crackTimeVal.textContent = data.crack_time;
  }
  if (criteriaContainer && data.criteria) {
    criteriaContainer.innerHTML = data.criteria.map(c => `
      <div class="col-md-6 mb-2">
        <div class="d-flex align-items-center">
          <i class="bi ${c.passed ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-muted'} me-2"></i>
          <div>
            <span class="small fw-semibold ${c.passed ? 'text-light' : 'text-muted'}">${c.name}</span>
            <div class="text-muted" style="font-size: 0.72rem;">${c.desc}</div>
          </div>
        </div>
      </div>
    `).join("");
  }
  if (tipsContainer && data.tips) {
    tipsContainer.innerHTML = data.tips.map(t => `
      <li class="small text-muted mb-1">${t}</li>
    `).join("");
  }
}

// 4. Suggest passwords based on user input
function fetchSuggestionsFromInput() {
  const inputEl = document.getElementById("smart-input-phrase");
  const baseInput = inputEl ? inputEl.value : "";
  const resultsContainer = document.getElementById("suggestions-results");
  if (!resultsContainer) return;

  resultsContainer.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-info"></div> Generating smart suggestions...</div>';

  fetch("/api/passwords/suggest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input: baseInput })
  })
  .then(r => r.json())
  .then(data => {
    if (data.status === "success" && data.suggestions) {
      resultsContainer.innerHTML = data.suggestions.map((s, idx) => `
        <div class="cyber-card p-3 mb-2 border-secondary">
          <div class="d-flex justify-content-between align-items-center mb-1">
            <span class="badge badge-cyan">${s.label}</span>
            <span class="badge bg-${s.analysis.strength_class}">${s.analysis.strength} (${s.analysis.entropy_bits} bits)</span>
          </div>
          <div class="input-group my-2">
            <input type="text" class="form-control mono-font font-monospace fw-bold text-info" value="${s.password}" id="sug-pwd-${idx}" readonly>
            <button class="btn btn-outline-info" type="button" onclick="copyToClipboard('${s.password}', 'copy-btn-${idx}')" id="copy-btn-${idx}">
              <i class="bi bi-clipboard"></i> Copy
            </button>
            <button class="btn btn-cyber-primary" type="button" onclick="useSuggestedPassword('${s.password}')">
              <i class="bi bi-box-arrow-in-down"></i> Use in Vault
            </button>
          </div>
          <div class="small text-muted">Crack Time: <span class="text-light">${s.analysis.crack_time}</span> • ${s.type}</div>
        </div>
      `).join("");
    }
  })
  .catch(err => {
    resultsContainer.innerHTML = '<div class="text-danger small">Error generating suggestions.</div>';
    console.error(err);
  });
}

function useSuggestedPassword(password) {
  const targetField = document.getElementById("modal-new-pwd");
  if (targetField) {
    targetField.value = password;
  }
  // If modal exists, open it or focus
  const saveModal = document.getElementById("addPasswordModal");
  if (saveModal && window.bootstrap) {
    const modalInstance = bootstrap.Modal.getOrCreateInstance(saveModal);
    modalInstance.show();
  }
  // Also populate analyzer
  const analyzerInput = document.getElementById("analyzer-input");
  if (analyzerInput) {
    analyzerInput.value = password;
    liveAnalyzePassword(password);
  }
}

// 5. Sample text helpers
function fillLinkCheckerSample(type) {
  const msgField = document.getElementById("message_text");
  const urlField = document.getElementById("target_url");
  if (!msgField || !urlField) return;

  if (type === "bank_phish") {
    msgField.value = "URGENT: Your Bank of America online access is suspended due to suspicious activity. Verify your identity immediately or your account will be permanently deactivated.";
    urlField.value = "http://192.168.1.105/bankofamerica-login-verify/auth.php";
  } else if (type === "lottery_scam") {
    msgField.value = "CONGRATULATIONS! You have won a $50,000 cash lottery prize from our international sweepstakes! Claim your payout instantly before expires.";
    urlField.value = "http://bit.ly/claim-prize-3891?ref=winner.tk";
  } else if (type === "legit_msg") {
    msgField.value = "Hi Sarah, can you please send over the Q3 financial report spreadsheet when you have a moment? Thanks!";
    urlField.value = "https://internal.company.com/reports/q3-summary";
  }
}

function fillMLScamSample(type) {
  const msgField = document.getElementById("ml_message_text");
  if (!msgField) return;

  if (type === "spam_prize") {
    msgField.value = "URGENT! You have won a 1 week FREE membership in our £100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010 T&C www.dbuk.net";
  } else if (type === "spam_credit") {
    msgField.value = "FREE MSG: Had your mobile 11 months or more? U R entitled to Update to the latest colour mobiles with camera for Free! Call 08002986030 now";
  } else if (type === "ham_normal") {
    msgField.value = "Hey Alex, are we still meeting for coffee tomorrow afternoon around 2 PM? Let me know!";
  } else if (type === "ham_work") {
    msgField.value = "I just pushed the latest security patches to the repository. Please review when free.";
  }
}
