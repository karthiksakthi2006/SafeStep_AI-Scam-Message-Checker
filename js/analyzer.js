/**
 * SafeStep Core Detection Engine
 * High-performance, client-side heuristic analyzer with URL defanging and plain-language reasoning.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js environment
    const rules = require('./rules.js');
    module.exports = factory(rules);
  } else {
    // Browser environment
    const win = (typeof window !== 'undefined' ? window : root);
    const rules = win.SafeStepRules || root.SafeStepRules || {
      SCAM_CATEGORIES: win.SCAM_CATEGORIES || root.SCAM_CATEGORIES || {},
      SCAM_PATTERNS: win.SCAM_PATTERNS || root.SCAM_PATTERNS || [],
      URL_SHORTENERS: win.URL_SHORTENERS || root.URL_SHORTENERS || [],
      RISKY_TLDS: win.RISKY_TLDS || root.RISKY_TLDS || [],
      BRAND_SPOOF_PATTERNS: win.BRAND_SPOOF_PATTERNS || root.BRAND_SPOOF_PATTERNS || []
    };
    const analyzer = factory(rules);
    root.SafeStepAnalyzer = analyzer;
    if (typeof window !== 'undefined') {
      window.SafeStepAnalyzer = analyzer;
    }
  }
}(typeof self !== 'undefined' ? self : this, function (rules) {
  'use strict';

  const {
    SCAM_CATEGORIES,
    SCAM_PATTERNS,
    URL_SHORTENERS,
    RISKY_TLDS,
    BRAND_SPOOF_PATTERNS
  } = rules;

  /**
   * Safe URL defanger: converts live links into non-clickable, benign text strings.
   * e.g., "https://evil-bank.xyz/login" -> "hxxps://evil-bank[.]xyz/login"
   */
  function defangUrl(url) {
    if (!url) return '';
    return url
      .replace(/^http:\/\//i, 'hxxp://')
      .replace(/^https:\/\//i, 'hxxps://')
      .replace(/\./g, '[.]')
      .replace(/@/g, '[@]');
  }

  /**
   * Safely extracts and analyzes URLs from message text without opening them.
   */
  function extractAndAnalyzeUrls(text) {
    const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`\[\]]+/gi;
    const matches = text.match(urlRegex) || [];
    const analyzedUrls = [];

    matches.forEach(rawUrl => {
      const defanged = defangUrl(rawUrl);
      const urlLower = rawUrl.toLowerCase();
      const reasons = [];
      let urlRiskWeight = 0;

      // Check 1: IP address used as hostname
      const ipMatch = rawUrl.match(/https?:\/\/(\d{1,3}\.){3}\d{1,3}/i);
      if (ipMatch) {
        reasons.push('Uses a direct numerical IP address instead of a recognized domain name. Legitimate services do not do this.');
        urlRiskWeight += 30;
      }

      // Check 2: Known URL shorteners
      const isShortened = URL_SHORTENERS.some(shortener => urlLower.includes(shortener));
      if (isShortened) {
        reasons.push('Uses a URL shortener service which hides the true web destination.');
        urlRiskWeight += 20;
      }

      // Check 3: High-risk or free TLDs
      const hasRiskyTld = RISKY_TLDS.some(tld => urlLower.includes(tld));
      if (hasRiskyTld) {
        reasons.push('Uses an unusual or low-cost top-level domain frequently associated with disposable phishing pages.');
        urlRiskWeight += 22;
      }

      // Check 4: Userinfo in URL (@ trick)
      if (rawUrl.includes('@')) {
        reasons.push('Contains an "@" symbol in the address, which is often used to deceive users about the true destination host.');
        urlRiskWeight += 28;
      }

      // Check 5: Lookalike / Brand Spoofing
      BRAND_SPOOF_PATTERNS.forEach(spoof => {
        if (spoof.pattern.test(urlLower) && !urlLower.includes(spoof.legitimate)) {
          reasons.push(`Lookalike domain mimicking ${spoof.brand} (Official is ${spoof.legitimate}).`);
          urlRiskWeight += 35;
        }
      });

      // Check 6: Insecure HTTP protocol on a sensitive prompt
      if (rawUrl.toLowerCase().startsWith('http://') && !ipMatch) {
        reasons.push('Uses unencrypted (HTTP) connection instead of secure HTTPS.');
        urlRiskWeight += 10;
      }

      // General link presence if no specific triggers
      if (reasons.length === 0) {
        reasons.push('Contains an external link from an unsolicited message. Always inspect the destination before interacting.');
        urlRiskWeight += 12;
      }

      analyzedUrls.push({
        rawUrl,
        defangedUrl: defanged,
        reasons,
        riskWeight: Math.min(urlRiskWeight, 40)
      });
    });

    return analyzedUrls;
  }

  /**
   * Main Message Analyzer
   * @param {string} rawText - The SMS, email, or chat text pasted by the user
   * @returns {Object} Comprehensive analysis result
   */
  function analyzeMessage(rawText) {
    const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    // 1. Validation & sanitization
    if (!rawText || typeof rawText !== 'string' || !rawText.trim()) {
      return {
        isValid: false,
        error: 'Please paste or type a message to analyze.',
        riskScore: 0,
        riskLevel: 'UNKNOWN',
        findings: [],
        safetySteps: [],
        links: []
      };
    }

    const text = rawText.trim();
    const findings = [];
    const categoryHits = {};
    let totalScore = 0;

    // 2. URL Extraction & Defanging
    const extractedUrls = extractAndAnalyzeUrls(text);
    if (extractedUrls.length > 0) {
      const highestUrlRisk = Math.max(...extractedUrls.map(u => u.riskWeight));
      totalScore += highestUrlRisk;

      const urlExplanations = [];
      extractedUrls.forEach(u => {
        u.reasons.forEach(r => {
          if (!urlExplanations.includes(r)) urlExplanations.push(r);
        });
      });

      findings.push({
        category: 'SUSPICIOUS_LINKS',
        categoryMeta: SCAM_CATEGORIES.SUSPICIOUS_LINKS,
        severity: highestUrlRisk >= 25 ? 'high' : 'medium',
        title: 'Unsolicited or Obfuscated Web Link Detected',
        matchedText: extractedUrls.map(u => u.defangedUrl).join(', '),
        explanation: 'The message contains links designed to direct you outside of your trusted app or email. All links below have been safely defanged to protect you.',
        details: urlExplanations,
        defangedLinks: extractedUrls.map(u => ({
          defanged: u.defangedUrl,
          reasons: u.reasons
        }))
      });

      categoryHits['SUSPICIOUS_LINKS'] = true;
    }

    // 3. Pattern Matching Across Scam Rules
    SCAM_PATTERNS.forEach(rule => {
      // Skip URL detection rule here since handled separately above
      if (rule.type === 'url_detection') return;

      const match = text.match(rule.regex);
      if (match) {
        // Prevent duplicate findings for the same category if already matched with equal or higher severity
        const categoryKey = rule.category;
        if (!categoryHits[categoryKey]) {
          categoryHits[categoryKey] = true;
          totalScore += rule.weight;

          findings.push({
            category: categoryKey,
            categoryMeta: SCAM_CATEGORIES[categoryKey],
            severity: rule.severity,
            title: rule.title,
            matchedSnippet: match[0],
            explanation: rule.explanation,
            whyScammersUseIt: SCAM_CATEGORIES[categoryKey].whyScammersUseIt
          });
        }
      }
    });

    // 4. Secondary heuristic: Excessive capitalization or urgency punctuation
    const capsMatch = text.match(/[A-Z\s!]{10,}/g);
    const exclamationCount = (text.match(/!/g) || []).length;
    if ((capsMatch && capsMatch.length > 0) || exclamationCount >= 3) {
      if (!categoryHits['URGENCY_THREATS']) {
        totalScore += 8;
      }
    }

    // Clamp score between 0 and 100
    const clampedScore = Math.min(100, Math.max(0, Math.round(totalScore)));
    const findingsCount = findings.length;

    // 5. Determine Warning Indication & UI Level (Non-Definitive)
    let riskLevel = 'LOW';
    let riskLabel = 'No common warning signs found';
    let riskColor = '#10b981'; // Emerald
    let riskBadgeClass = 'risk-low';
    let riskSummary = 'No common warning signs were detected in this message. Please note: This does not prove the message is safe. Scammers continually develop new techniques—always verify independently.';

    if (findingsCount > 0) {
      const plural = findingsCount === 1 ? 'sign' : 'signs';
      riskLabel = `${findingsCount} warning ${plural} found`;
      
      if (clampedScore >= 70 || findingsCount >= 3) {
        riskLevel = 'HIGH';
        riskColor = '#ef4444'; // Crimson
        riskBadgeClass = 'risk-high';
        riskSummary = `${findingsCount} common scam warning ${plural} detected. Exercise extreme caution. Do not click links, share private codes, or send money.`;
      } else if (clampedScore >= 35 || findingsCount >= 2) {
        riskLevel = 'MEDIUM';
        riskColor = '#f59e0b'; // Amber
        riskBadgeClass = 'risk-medium';
        riskSummary = `${findingsCount} warning ${plural} detected. This message contains patterns frequently used in scam attempts.`;
      } else {
        riskLevel = 'CAUTION';
        riskColor = '#3b82f6'; // Blue
        riskBadgeClass = 'risk-caution';
        riskSummary = `1 cautionary warning sign detected. Always confirm the sender's identity through official channels.`;
      }
    }

    // 6. Practical Safety Steps
    // Core universal guidelines guaranteed for EVERY result
    const safetySteps = [
      {
        id: 'no_otp_passwords',
        icon: '🛑',
        title: 'Do not share passwords, PINs, or OTPs',
        instruction: 'Legitimate organizations, banks, and customer support representatives will never ask you to disclose or read back your one-time passwords (OTPs), login passwords, or secret PINs.',
        isCrucial: true
      },
      {
        id: 'avoid_links_payments',
        icon: '🚫',
        title: 'Avoid unexpected links and pressured payments',
        instruction: 'Never tap or click unexpected links. Refuse rushed requests to send payments via gift cards, cryptocurrency, or wire transfers, which cannot be reversed.',
        isCrucial: true
      },
      {
        id: 'independent_verification',
        icon: '🏢',
        title: 'Independently contact the organization',
        instruction: 'Verify unexpected requests by contacting the organization independently using its official app, verified website, or known phone number on the back of your card—never use the contact info in the message.',
        isCrucial: true
      }
    ];

    // Context-specific recommendations based on detected categories
    if (categoryHits['CREDENTIALS_OTP']) {
      safetySteps.push({
        id: 'action_otp_compromised',
        icon: '🔐',
        title: 'Immediate Action for Shared Credentials',
        instruction: 'If you already shared a code or password, immediately visit the official website directly, change your account password, and call your provider\'s fraud helpline.',
        isCrucial: true
      });
    }

    if (categoryHits['SUSPICIOUS_LINKS']) {
      safetySteps.push({
        id: 'action_link_safety',
        icon: '🛡️',
        title: 'Safely Handling Links',
        instruction: 'We have defanged all URLs in the message above so they cannot be clicked. If you opened this link on your phone/computer, close the tab, do not enter any credentials, and run a malware scan if prompted to download a file.',
        isCrucial: false
      });
    }

    if (categoryHits['PAYMENT_REQUESTS']) {
      safetySteps.push({
        id: 'action_payment_stop',
        icon: '💳',
        title: 'Stop Payment Immediately',
        instruction: 'If you sent money through a bank transfer or debit card, call your bank\'s emergency fraud department right now to request a payment recall.',
        isCrucial: false
      });
    }

    // Reporting step
    safetySteps.push({
      id: 'report_spam',
      icon: '📢',
      title: 'Report the Message',
      instruction: 'Forward suspicious SMS messages to 7726 (SPAM) for free on most carriers, or report the email to your provider\'s phishing department.',
      isCrucial: false
    });

    const endTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const durationMs = Math.round((endTime - startTime) * 100) / 100;

    return {
      isValid: true,
      originalText: text,
      charCount: text.length,
      wordCount: text.trim().split(/\s+/).filter(Boolean).length,
      riskScore: clampedScore,
      riskLevel,
      riskLabel,
      riskColor,
      riskBadgeClass,
      riskSummary,
      findingsCount: findings.length,
      findings,
      safetySteps,
      extractedUrls,
      metadata: {
        analysisMode: 'Local Rules Engine (100% Client-Side Privacy)',
        analyzedAt: new Date().toISOString(),
        executionTimeMs: durationMs,
        disclaimer: 'Guidance only: SafeStep is an educational advisory tool. It cannot prove that a message is safe or fraudulent. Attackers continuously create novel scams; always exercise independent verification.'
      }
    };
  }

  return {
    analyzeMessage,
    defangUrl,
    extractAndAnalyzeUrls
  };
}));
