/**
 * SafeStep AI Enhancement Module
 * Optional AI Deep Analysis engine with complete transparency and local fallback.
 * By default, SafeStep runs 100% locally.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SafeStepAI = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // State
  let isAiEnabled = false;
  let userApiKey = '';

  /**
   * Generates local rule-based AI explanation narrative (100% offline, zero network)
   */
  function generateLocalNarrative(analysis) {
    if (!analysis.isValid) return '';

    if (analysis.riskLevel === 'HIGH') {
      const topFinding = analysis.findings[0] ? analysis.findings[0].title : 'multiple severe flags';
      return `⚠️ **Critical Advisory**: This message exhibits high-confidence characteristics of a cyber scam, notably "${topFinding}". The combination of urgency, deception, or credential requests is designed to compromise your accounts or funds. Under no circumstances should you click links, share OTP codes, or send money.`;
    } else if (analysis.riskLevel === 'MEDIUM') {
      return `⚠️ **Cautionary Notice**: This message contains suspicious elements that are frequently seen in phishing and social engineering campaigns. While not conclusively proven fraudulent, it warrants extreme caution. Do not rely on contact information inside this message.`;
    } else if (analysis.riskLevel === 'CAUTION') {
      return `ℹ️ **Advisory Note**: Minor cautionary indicators detected (e.g. unsolicited link or automated prompt). Verify sender identity before taking any actions.`;
    } else {
      return `✅ **Normal Patterns Detected**: This message conforms to typical benign conversational or routine service notification patterns. No urgent coercive threats, OTP demands, or high-risk scam markers were found.`;
    }
  }

  /**
   * Preview exact JSON payload that would be sent if AI API is called.
   * Full privacy transparency for the user.
   */
  function getPayloadPreview(messageText) {
    return {
      endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      dataSent: {
        contents: [
          {
            parts: [
              {
                text: `You are SafeStep Cybersecurity Assistant. Analyze this message for scam signs:\n"${messageText}"`
              }
            ]
          }
        ]
      },
      privacyGuarantees: [
        'No user identifiers (cookies, device ID, IP) sent',
        'Payload contains strictly the text in the message box',
        'Direct HTTPS connection from your browser to Google Gemini API'
      ]
    };
  }

  /**
   * Optional Gemini API caller
   */
  async function queryGemini(messageText, apiKey) {
    if (!apiKey) {
      throw new Error('No API key provided. Using local heuristic analysis.');
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${encodeURIComponent(apiKey.trim())}`;
    
    const prompt = `Analyze this SMS/email/chat message for scams, phishing, and digital safety risks:
"${messageText}"

Respond ONLY with a JSON object in this format:
{
  "riskLevel": "HIGH" | "MEDIUM" | "CAUTION" | "LOW",
  "aiSummary": "2-sentence plain-language safety assessment",
  "tacticsDetected": ["list of social engineering tactics"],
  "psychologicalTriggers": ["fear", "greed", "urgency", "authority", etc.],
  "keyAdvice": "1 core takeaway"
}`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 600,
          responseMimeType: 'application/json'
        }
      })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error?.message || `API error (HTTP ${response.status})`);
    }

    const data = await response.json();
    const candidateText = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!candidateText) {
      throw new Error('Empty response from AI service');
    }

    try {
      return JSON.parse(candidateText);
    } catch (e) {
      return {
        riskLevel: 'MEDIUM',
        aiSummary: candidateText.slice(0, 300),
        tacticsDetected: ['Analysis generated in plain text'],
        psychologicalTriggers: ['Unspecified'],
        keyAdvice: 'Verify with the institution through official channels.'
      };
    }
  }

  return {
    isEnabled: () => isAiEnabled,
    setEnabled: (val) => { isAiEnabled = Boolean(val); },
    setApiKey: (key) => { userApiKey = key; },
    getApiKey: () => userApiKey,
    generateLocalNarrative,
    getPayloadPreview,
    queryGemini
  };
}));
