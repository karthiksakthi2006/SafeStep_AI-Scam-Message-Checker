/**
 * SafeStep UI Controller & Application Logic
 * Wires the Check Message button, Clear button, one-click sample buttons,
 * character/word counters, dynamic results panel, and test scenarios.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Inputs & Actions
  const messageInput = document.getElementById('messageInput');
  const checkBtn = document.getElementById('checkBtn');
  const clearBtn = document.getElementById('clearBtn');
  const testSuiteBtn = document.getElementById('testSuiteBtn');
  const btnSampleSuspicious = document.getElementById('btnSampleSuspicious');
  const btnSampleOrdinary = document.getElementById('btnSampleOrdinary');
  const validationAlert = document.getElementById('validationAlert');
  const validationMessage = document.getElementById('validationMessage');
  const charCounter = document.getElementById('charCounter');
  const wordCounter = document.getElementById('wordCounter');
  const themeToggleBtn = document.getElementById('themeToggleBtn');

  // DOM Elements - Results Area
  const resultsEmptyState = document.getElementById('resultsEmptyState');
  const resultsActiveState = document.getElementById('resultsActiveState');
  const riskIndicatorBanner = document.getElementById('riskIndicatorBanner');
  const riskLevelBadge = document.getElementById('riskLevelBadge');
  const riskHeadline = document.getElementById('riskHeadline');
  const riskSummaryText = document.getElementById('riskSummaryText');
  const riskMeterFill = document.getElementById('riskMeterFill');
  const riskScoreNum = document.getElementById('riskScoreNum');
  const findingsList = document.getElementById('findingsList');
  const findingsCountBadge = document.getElementById('findingsCountBadge');
  const linkInspectorContainer = document.getElementById('linkInspectorContainer');
  const safetyStepsList = document.getElementById('safetyStepsList');
  const copyAdviceBtn = document.getElementById('copyAdviceBtn');
  const toastNotice = document.getElementById('toastNotice');

  // DOM Elements - Test Modal
  const testSuiteModal = document.getElementById('testSuiteModal');
  const closeTestSuiteModal = document.getElementById('closeTestSuiteModal');
  const runAllTestsBtn = document.getElementById('runAllTestsBtn');

  // State
  let currentAnalysis = null;
  const CIRCUMFERENCE = 219.9; // 2 * PI * 35 for SVG gauge circle

  // --- Theme Management ---
  const savedTheme = localStorage.getItem('safestep_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);

  themeToggleBtn.addEventListener('click', () => {
    const active = document.documentElement.getAttribute('data-theme');
    const newTheme = active === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('safestep_theme', newTheme);
    updateThemeIcon(newTheme);
  });

  function updateThemeIcon(theme) {
    themeToggleBtn.innerHTML = theme === 'light' ? '🌙' : '☀️';
    themeToggleBtn.setAttribute('title', `Switch to ${theme === 'light' ? 'dark' : 'light'} mode`);
  }

  // --- Character & Word Counters ---
  messageInput.addEventListener('input', () => {
    updateCounters();
    if (messageInput.value.trim().length > 0) {
      hideValidation();
    }
  });

  function updateCounters() {
    const text = messageInput.value;
    const charCount = text.length;
    const words = text.trim() ? text.trim().split(/\s+/).filter(Boolean).length : 0;
    charCounter.textContent = `${charCount} character${charCount === 1 ? '' : 's'}`;
    wordCounter.textContent = `${words} word${words === 1 ? '' : 's'}`;
  }

  // --- Validation Alerts ---
  function showValidation(msg) {
    validationMessage.textContent = msg;
    validationAlert.classList.add('visible');
    messageInput.focus();
  }

  function hideValidation() {
    validationAlert.classList.remove('visible');
  }

  // --- One-Click Sample Buttons ---
  btnSampleSuspicious.addEventListener('click', () => {
    const samples = window.SAMPLE_MESSAGES || (typeof SAMPLE_MESSAGES !== 'undefined' ? SAMPLE_MESSAGES : null);
    if (samples && samples.suspicious && samples.suspicious[0]) {
      messageInput.value = samples.suspicious[0].text;
    } else {
      messageInput.value = 'URGENT: Your First National Bank account has been restricted due to unauthorized login attempts. Immediate action required within 24 hours to prevent permanent closure. Verify your identity now at http://firstnational-security-login.xyz/verify to restore access.';
    }
    hideValidation();
    updateCounters();
    runAnalysis();
    showToast('Loaded suspicious sample message.');
  });

  btnSampleOrdinary.addEventListener('click', () => {
    const samples = window.SAMPLE_MESSAGES || (typeof SAMPLE_MESSAGES !== 'undefined' ? SAMPLE_MESSAGES : null);
    if (samples && samples.ordinary && samples.ordinary[0]) {
      messageInput.value = samples.ordinary[0].text;
    } else {
      messageInput.value = 'Hi Alex, this is a reminder from Cedar Grove Family Health of your upcoming appointment with Dr. Taylor tomorrow, Oct 2nd at 10:15 AM. Please reply C to confirm, or call our reception desk at (555) 018-9920 if you need to reschedule.';
    }
    hideValidation();
    updateCounters();
    runAnalysis();
    showToast('Loaded ordinary benign message.');
  });

  // --- Check Message Handler ---
  checkBtn.addEventListener('click', runAnalysis);

  function runAnalysis() {
    const text = messageInput.value;

    // 1. If text box is empty, show helpful message
    if (!text || !text.trim()) {
      showValidation('Please paste or type an SMS, email, or chat message before checking.');
      return;
    }

    hideValidation();

    try {
      const analyzer = window.SafeStepAnalyzer || (typeof SafeStepAnalyzer !== 'undefined' ? SafeStepAnalyzer : null);
      if (!analyzer) {
        throw new Error('SafeStepAnalyzer engine not found.');
      }

      // 2. Perform client-side heuristic analysis
      const analysis = analyzer.analyzeMessage(text);
      currentAnalysis = analysis;

      // 3. Immediately display the results panel without page refresh
      displayResults(analysis);
    } catch (err) {
      console.error('SafeStep Analysis Error:', err);
      showToast('Error during analysis. Please check console.');
    }
  }

  // --- Clear Button Handler ---
  clearBtn.addEventListener('click', resetAll);

  function resetAll() {
    messageInput.value = '';
    updateCounters();
    hideValidation();
    
    // Reset Results View back to empty state
    resultsActiveState.classList.remove('visible');
    resultsEmptyState.style.display = 'flex';
    currentAnalysis = null;
    showToast('Cleared message input and results.');
  }

  // --- Render Results Panel ---
  function displayResults(analysis) {
    resultsEmptyState.style.display = 'none';
    resultsActiveState.classList.add('visible');

    const count = analysis.findings.length;

    // 1. Simple Indication of Warning Signs Found
    riskIndicatorBanner.className = `risk-indicator-banner ${analysis.riskBadgeClass}`;
    
    if (count === 0) {
      riskLevelBadge.textContent = 'NO COMMON WARNING SIGNS';
      riskHeadline.textContent = 'No common warning signs found';
      riskSummaryText.textContent = 'No common warning signs were detected in this message. Please note: This does not prove the message is safe. Scammers continually develop new techniques—always verify independently through official channels.';
      
      // Gauge shows 0
      riskMeterFill.style.stroke = '#10b981';
      riskMeterFill.style.strokeDashoffset = CIRCUMFERENCE;
      riskScoreNum.textContent = '0';
    } else {
      const plural = count === 1 ? 'SIGN' : 'SIGNS';
      riskLevelBadge.textContent = `${count} WARNING ${plural} FOUND`;
      riskHeadline.textContent = `${count} Warning ${count === 1 ? 'Sign' : 'Signs'} Detected`;
      riskSummaryText.textContent = `${count} common scam warning ${count === 1 ? 'sign was' : 'signs were'} found in this message. Exercise extreme caution. Do not click links, share private credentials, or send money.`;

      // Gauge displays count
      const offset = CIRCUMFERENCE - Math.min(1, count / 5) * CIRCUMFERENCE;
      riskMeterFill.style.stroke = analysis.riskColor;
      riskMeterFill.style.strokeDashoffset = offset;
      riskScoreNum.textContent = count;
    }

    // 2. List Each Warning Sign Found with Plain-Language Explanation
    findingsCountBadge.textContent = `${count} ${count === 1 ? 'Sign' : 'Signs'}`;
    findingsList.innerHTML = '';

    if (count === 0) {
      const cleanCard = document.createElement('div');
      cleanCard.className = 'finding-card';
      cleanCard.innerHTML = `
        <div class="finding-header">
          <span class="finding-category-tag" style="background:rgba(16, 185, 129, 0.15); color:#10b981; border: 1px solid rgba(16, 185, 129, 0.3);">
            ✅ No Red Flags Found
          </span>
          <span class="finding-severity" style="color:#10b981;">Advisory Guidance</span>
        </div>
        <div class="finding-title">No Common Scam Warning Signs Detected</div>
        <div class="finding-explanation">
          This message does not appear to contain urgent threats, requests for passwords/PINs/OTPs, suspicious links, unusual payment demands, fake prizes, or account verification scares.
        </div>
        <div class="finding-why" style="border-left-color: #10b981;">
          ⚠️ <strong>Important Reminder:</strong> An absence of detected signs does not prove a message is safe or authentic. If anything feels unusual or unexpected, verify with the sender independently.
        </div>
      `;
      findingsList.appendChild(cleanCard);
    } else {
      analysis.findings.forEach(finding => {
        const card = document.createElement('div');
        card.className = 'finding-card';

        const categoryTag = finding.categoryMeta 
          ? `<span class="finding-category-tag ${finding.categoryMeta.badgeClass}">${finding.categoryMeta.icon} ${finding.categoryMeta.name}</span>`
          : `<span class="finding-category-tag">${finding.category}</span>`;

        let snippetHtml = '';
        if (finding.matchedSnippet) {
          snippetHtml = `<div class="finding-snippet">Detected text snippet: "${escapeHtml(finding.matchedSnippet)}"</div>`;
        }

        let whyHtml = '';
        if (finding.whyScammersUseIt) {
          whyHtml = `<div class="finding-why">💡 <strong>Why scammers use this:</strong> ${escapeHtml(finding.whyScammersUseIt)}</div>`;
        }

        card.innerHTML = `
          <div class="finding-header">
            ${categoryTag}
            <span class="finding-severity">${finding.severity} severity</span>
          </div>
          <div class="finding-title">${escapeHtml(finding.title)}</div>
          ${snippetHtml}
          <div class="finding-explanation">${escapeHtml(finding.explanation)}</div>
          ${whyHtml}
        `;
        findingsList.appendChild(card);
      });
    }

    // 3. Render Defanged Link Inspector (Inert & Safe)
    if (analysis.extractedUrls && analysis.extractedUrls.length > 0) {
      linkInspectorContainer.style.display = 'block';
      linkInspectorContainer.innerHTML = `
        <div class="link-inspector-box">
          <div class="link-inspector-title">
            <span>🛡️ Safely Defanged Web Links (${analysis.extractedUrls.length})</span>
          </div>
          <p class="link-inspector-desc">
            To prevent accidental clicks or drive-by downloads, all links found in the message are safely defanged and rendered non-clickable.
          </p>
          ${analysis.extractedUrls.map(u => `
            <div class="defanged-link-item">
              <span class="defanged-url-text">${escapeHtml(u.defangedUrl)}</span>
              ${u.reasons.map(r => `<div class="defanged-url-flag">⚠️ ${escapeHtml(r)}</div>`).join('')}
            </div>
          `).join('')}
        </div>
      `;
    } else {
      linkInspectorContainer.style.display = 'none';
      linkInspectorContainer.innerHTML = '';
    }

    // 4. Practical Next Steps to Stay Safe
    safetyStepsList.innerHTML = '';
    analysis.safetySteps.forEach((step, idx) => {
      const stepItem = document.createElement('div');
      stepItem.className = 'safety-step-item';
      stepItem.innerHTML = `
        <input type="checkbox" id="step_check_${idx}" class="step-checkbox" aria-label="Mark safety step as completed">
        <div class="step-content">
          <label for="step_check_${idx}" class="step-title" style="cursor:pointer;">
            <span>${step.icon}</span> ${escapeHtml(step.title)}
          </label>
          <div class="step-instruction">${escapeHtml(step.instruction)}</div>
        </div>
      `;
      safetyStepsList.appendChild(stepItem);
    });
  }

  // --- Copy Advice Button ---
  copyAdviceBtn.addEventListener('click', () => {
    if (!currentAnalysis) return;

    let textToCopy = `SafeStep Security Guidance Report\n`;
    textToCopy += `Summary: ${currentAnalysis.riskHeadline}\n`;
    textToCopy += `${currentAnalysis.riskSummary}\n\n`;

    if (currentAnalysis.findings.length > 0) {
      textToCopy += `Warning Signs Found:\n`;
      currentAnalysis.findings.forEach(f => {
        textToCopy += `- ${f.title}: ${f.explanation}\n`;
      });
      textToCopy += `\n`;
    }

    textToCopy += `Practical Next Steps to Stay Safe:\n`;
    currentAnalysis.safetySteps.forEach(s => {
      textToCopy += `• ${s.title}: ${s.instruction}\n`;
    });

    textToCopy += `\nDisclaimer: Guidance only; does not prove a message is safe or fraudulent.`;

    navigator.clipboard.writeText(textToCopy)
      .then(() => showToast('📋 Safety advice copied to clipboard!'))
      .catch(() => showToast('Could not copy automatically.'));
  });

  // --- Toast Notification ---
  function showToast(msg) {
    toastNotice.textContent = msg;
    toastNotice.classList.add('show');
    setTimeout(() => {
      toastNotice.classList.remove('show');
    }, 2800);
  }

  // --- Interactive Test Suite Modal ---
  testSuiteBtn.addEventListener('click', () => {
    testSuiteModal.classList.add('visible');
    document.body.style.overflow = 'hidden';
  });

  closeTestSuiteModal.addEventListener('click', () => {
    testSuiteModal.classList.remove('visible');
    document.body.style.overflow = '';
  });

  testSuiteModal.addEventListener('click', (e) => {
    if (e.target === testSuiteModal) {
      testSuiteModal.classList.remove('visible');
      document.body.style.overflow = '';
    }
  });

  function getSuspiciousSampleText() {
    const s = window.SAMPLE_MESSAGES || (typeof SAMPLE_MESSAGES !== 'undefined' ? SAMPLE_MESSAGES : null);
    return (s && s.suspicious && s.suspicious[0])
      ? s.suspicious[0].text
      : 'URGENT: Your First National Bank account has been restricted due to unauthorized login attempts. Immediate action required within 24 hours to prevent permanent closure. Verify your identity now at http://firstnational-security-login.xyz/verify to restore access.';
  }

  function getOrdinarySampleText() {
    const s = window.SAMPLE_MESSAGES || (typeof SAMPLE_MESSAGES !== 'undefined' ? SAMPLE_MESSAGES : null);
    return (s && s.ordinary && s.ordinary[0])
      ? s.ordinary[0].text
      : 'Hi Alex, this is a reminder from Cedar Grove Family Health of your upcoming appointment with Dr. Taylor tomorrow, Oct 2nd at 10:15 AM. Please reply C to confirm, or call our reception desk at (555) 018-9920 if you need to reschedule.';
  }

  // Define 4 Manual Test Scenarios
  const TEST_SCENARIOS = [
    {
      id: 'test_suspicious',
      name: 'Scenario 1: Suspicious Phishing Text',
      desc: 'Tests detection of urgent account restriction, fake bank link, and credential verification.',
      getSampleText: getSuspiciousSampleText,
      validate: (res) => res.isValid && res.findings.length >= 2
    },
    {
      id: 'test_ordinary',
      name: 'Scenario 2: Ordinary Benign Message',
      desc: 'Tests benign appointment reminder to ensure “No common warning signs found” result.',
      getSampleText: getOrdinarySampleText,
      validate: (res) => res.isValid && res.findings.length === 0
    },
    {
      id: 'test_empty',
      name: 'Scenario 3: Empty Input Validation',
      desc: 'Tests checking an empty box to ensure helpful validation alert is displayed without crashing.',
      getSampleText: () => '',
      validate: (res) => !res.isValid && res.error && res.error.includes('Please paste or type')
    },
    {
      id: 'test_clear',
      name: 'Scenario 4: Clear Button Reset',
      desc: 'Tests that input text, counters, and results are properly wiped when Clear is selected.',
      getSampleText: () => 'Sample text to clear',
      validate: () => true
    }
  ];

  runAllTestsBtn.addEventListener('click', () => {
    TEST_SCENARIOS.forEach(scenario => {
      const statusEl = document.getElementById(`${scenario.id}_status`);
      const detailsEl = document.getElementById(`${scenario.id}_details`);

      if (scenario.id === 'test_clear') {
        messageInput.value = 'Sample test text';
        updateCounters();
        resetAll();
        const passed = (messageInput.value === '' && !resultsActiveState.classList.contains('visible'));
        updateTestStatus(statusEl, detailsEl, passed, 'Clear properly emptied input and reset results.');
      } else {
        const textToAnalyze = scenario.getSampleText ? scenario.getSampleText() : (scenario.sampleText || '');
        const analyzer = window.SafeStepAnalyzer || (typeof SafeStepAnalyzer !== 'undefined' ? SafeStepAnalyzer : null);
        const res = analyzer ? analyzer.analyzeMessage(textToAnalyze) : { isValid: false, findings: [] };
        const passed = scenario.validate(res);
        const detailMsg = passed
          ? `Verified: ${res.findings ? res.findings.length + ' signs found' : 'Validation alert triggered'}.`
          : 'Verification failed to meet criteria.';
        updateTestStatus(statusEl, detailsEl, passed, detailMsg);
      }
    });

    showToast('✨ All 4 test scenarios evaluated successfully!');
  });

  function updateTestStatus(statusEl, detailsEl, passed, message) {
    statusEl.className = `test-scenario-status ${passed ? 'status-passed' : 'status-failed'}`;
    statusEl.textContent = passed ? '✅ PASSED' : '❌ FAILED';
    if (detailsEl) {
      detailsEl.textContent = message;
      detailsEl.style.color = passed ? '#34d399' : '#f87171';
    }
  }

  // Individual scenario run buttons in modal
  document.querySelectorAll('.test-scenario-run-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const scenarioId = btn.dataset.scenario;
      const scenario = TEST_SCENARIOS.find(s => s.id === scenarioId);
      if (!scenario) return;

      testSuiteModal.classList.remove('visible');
      document.body.style.overflow = '';

      if (scenario.id === 'test_clear') {
        messageInput.value = 'Sample text to clear';
        updateCounters();
        resetAll();
        showToast('Clear button demonstrated.');
      } else if (scenario.id === 'test_empty') {
        messageInput.value = '';
        updateCounters();
        runAnalysis();
      } else {
        messageInput.value = scenario.getSampleText ? scenario.getSampleText() : '';
        updateCounters();
        runAnalysis();
        showToast(`Loaded and checked: ${scenario.name}`);
      }
    });
  });

  // Utility: Escape HTML
  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
