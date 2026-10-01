/**
 * SafeStep Rule Engine Database
 * Definitive pattern dictionaries, regex matchers, severity weights, and plain-language explanations.
 * Runs 100% locally in the client browser - no data ever leaves the device.
 */

const SCAM_CATEGORIES = {
  URGENCY_THREATS: {
    id: 'urgency_threats',
    name: 'Urgent demands or threats',
    icon: '⚡',
    badgeClass: 'badge-urgency',
    description: 'Pressures you with panic, tight deadlines, or severe consequences so you act without thinking.',
    whyScammersUseIt: 'Fraudsters know that fear and haste disable critical thinking. They rush you into mistakes before you can verify facts.'
  },
  CREDENTIALS_OTP: {
    id: 'credentials_otp',
    name: 'Requests for passwords, PINs, or OTPs',
    icon: '🔑',
    badgeClass: 'badge-otp',
    description: 'Directly asks for one-time passwords, login codes, PINs, or confidential credentials.',
    whyScammersUseIt: 'Legitimate organizations NEVER ask for your secret codes or passwords. Scammers use your OTP to bypass two-factor authentication and drain accounts.'
  },
  SUSPICIOUS_LINKS: {
    id: 'suspicious_links',
    name: 'Links or shortened URLs',
    icon: '🔗',
    badgeClass: 'badge-link',
    description: 'Contains obfuscated, shortened, lookalike, or high-risk web addresses designed to clone official portals.',
    whyScammersUseIt: 'Fake links lead to credential-stealing phishing sites or trigger silent malware downloads.'
  },
  PAYMENT_REQUESTS: {
    id: 'payment_requests',
    name: 'Payment or money transfer requests',
    icon: '💳',
    badgeClass: 'badge-payment',
    description: 'Demands payment via irreversible or untraceable methods like gift cards, cryptocurrency, or wire transfers.',
    whyScammersUseIt: 'Once cryptocurrency or gift card codes are sent, they are nearly impossible to trace or reverse.'
  },
  UNEXPECTED_PRIZES: {
    id: 'unexpected_prizes',
    name: 'Unexpected prizes or rewards',
    icon: '🎁',
    badgeClass: 'badge-prize',
    description: 'Promises large sums of money, lottery winnings, or expensive gifts for competitions you never entered.',
    whyScammersUseIt: 'Greed or curiosity is used as bait. Scammers require an "advance fee" or personal info to claim the non-existent prize.'
  },
  ACCOUNT_VERIFICATION: {
    id: 'account_verification',
    name: 'Requests to verify account or identity details',
    icon: '🛡️',
    badgeClass: 'badge-verify',
    description: 'Claims your account is blocked, flagged for fraud, or requires urgent identity re-verification.',
    whyScammersUseIt: 'Impersonating your bank, cloud provider, or streaming service lets scammers harvest Social Security numbers, login credentials, and billing data.'
  }
};

const SCAM_PATTERNS = [
  // 1. URGENCY & THREATS
  {
    category: 'URGENCY_THREATS',
    severity: 'high',
    weight: 25,
    regex: /\b(within\s*(24|12|48|2|1|few)\s*(hours?|hrs?|minutes?|mins?)|immediate(ly)?\s*(action|response)\s*required|act\s*(now|immediately)|reply\s*(immediately|urgently|asap)|call\s*immediately|final\s*(warning|notice)|account\s*will\s*be\s*(suspended|terminated|closed|disabled|deleted)|failure\s*to\s*comply|legal\s*action\s*(will\s*be\s*taken|pending)|arrest\s*warrant|law\s*enforcement|call\s*immediately\s*to\s*avoid|urgent\s*notice|time\s*sensitive|expires\s*today)\b/i,
    title: 'High-Pressure Urgency or Legal Threat',
    explanation: 'The message creates an artificial deadline or warns of extreme penalties (suspension, arrest, or legal action) to force you into acting before verifying the claims.'
  },
  {
    category: 'URGENCY_THREATS',
    severity: 'medium',
    weight: 16,
    regex: /\b(urgently?|asap|do\s*not\s*ignore|last\s*chance|before\s*it('?s|\s*is)\s*too\s*late|action\s*needed|cancel\s*this\s*request)\b/i,
    title: 'Urgent Call to Action',
    explanation: 'Uses pressure words like "ASAP" or "Last Chance" to provoke a hurried emotional response.'
  },

  // 2. CREDENTIALS, PASSWORDS, PINS & OTPS
  {
    category: 'CREDENTIALS_OTP',
    severity: 'critical',
    weight: 50,
    regex: /\b(one[- ]time\s*pass(word)?|otp|verification\s*code|security\s*code|passcode|6[- ]digit\s*code|pin\s*number|secret\s*pin|send\s*(us|me)\s*the\s*(code|otp)|never\s*share\s*this\s*code.*?reply|reply\s*with\s*(the\s*)?(code|otp|pin)|share\s*(your\s*)?(password|pin|otp))\b/i,
    title: 'Direct Request for Secret OTP or PIN',
    explanation: 'The message attempts to obtain your One-Time Password (OTP) or PIN. No legitimate company, bank, or support representative will ever ask you to read or reply with your secret security codes.'
  },
  {
    category: 'CREDENTIALS_OTP',
    severity: 'high',
    weight: 35,
    regex: /\b(enter\s*your\s*(password|credentials|login\s*details|secret\s*key)|confirm\s*your\s*password|reset\s*your\s*password\s*here|share\s*your\s*password)\b/i,
    title: 'Password or Credential Harvesting',
    explanation: 'Prompts you to input your login password or credentials. Legitimate security alerts direct you to log in via official apps, not embedded external prompts.'
  },

  // 3. SUSPICIOUS LINKS
  {
    category: 'SUSPICIOUS_LINKS',
    severity: 'high',
    weight: 25,
    type: 'url_detection',
    title: 'Potentially Hazardous or Obfuscated Web Link',
    explanation: 'The message contains links using URL shorteners, IP addresses, unusual top-level domains, or lookalike brand spellings that disguise the true destination.'
  },

  // 4. PAYMENT REQUESTS & PRESSURED TRANSFERS
  {
    category: 'PAYMENT_REQUESTS',
    severity: 'critical',
    weight: 35,
    regex: /\b(gift\s*card(s)?|google\s*play\s*card|apple\s*(gift\s*)?card|steam\s*(gift\s*)?card|itunes\s*card|crypto(currency)?|bitcoin|btc\s*wallet|western\s*union|moneygram|wire\s*transfer|pay\s*via\s*zelle|urgent\s*venmo|deposit\s*fee\s*to\s*(release|claim)|advance\s*fee|processing\s*fee\s*of\s*\$?\d+)\b/i,
    title: 'Request for Untraceable / Irreversible Payment',
    explanation: 'Asks for money via gift cards, cryptocurrency, or wire transfer. These methods are preferred by scammers because they bypass standard fraud protections and cannot be reversed.'
  },
  {
    category: 'PAYMENT_REQUESTS',
    severity: 'medium',
    weight: 20,
    regex: /\b(unpaid\s*bill|toll\s*fee|unpaid\s*invoice|delivery\s*fee\s*of\s*\$?\d+|customs\s*fee|overdue\s*payment|settle\s*immediately)\b/i,
    title: 'Unexpected Fee or Toll Claim',
    explanation: 'Claims you owe an unexpected toll, parcel fee, or overdue invoice. Scammers use small dollar amounts to trick people into entering payment card details on spoofed payment gateways.'
  },

  // 5. UNEXPECTED PRIZES & REWARDS
  {
    category: 'UNEXPECTED_PRIZES',
    severity: 'high',
    weight: 30,
    regex: /\b(congratulations|congrats|you\s*(have\s*)?won|selected\s*as\s*(a|the)\s*(lucky\s*)?winner|lottery\s*(draw|prize)|cash\s*prize|reward\s*of\s*\$?[\d,]+(\.\d+)?|claim\s*your\s*(prize|iphone|reward|voucher|gift)|free\s*(iphone|gift\s*card|giveaway)|exclusive\s*winner|inheritance\s*fund|compensation\s*fund)\b/i,
    title: 'Unsolicited Prize or Giveaway Bait',
    explanation: 'Claims you have won a competition, lottery, or luxury item. Real lotteries and sweepstakes do not contact winners via random SMS or email without prior registration.'
  },

  // 6. ACCOUNT VERIFICATION / IMPERSONATION
  {
    category: 'ACCOUNT_VERIFICATION',
    severity: 'high',
    weight: 25,
    regex: /\b(verify\s*your\s*(account|identity|identity\s*details|profile)|update\s*(your\s*)?(billing|payment)\s*(info|information)|kyc\s*(update|verification|suspended)|unauthorized\s*(activity|login|transaction)\s*(detected)?|unrecognized\s*(sign[- ]in|login)|suspicious\s*sign[- ]in|security\s*alert.*?click|confirm\s*your\s*ssn|social\s*security\s*number|reactivate\s*your\s*(service|account)|membership\s*renewal\s*fee)\b/i,
    title: 'Unsolicited Account Verification / Security Scare',
    explanation: 'Impersonates a bank, institution, or online platform claiming an issue with your account. They trick you into "re-verifying" identity credentials on their imposter form.'
  }
];

// Common URL Shorteners and High-Risk TLDs
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'cutt.ly', 'ow.ly', 'buff.ly',
  'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink'
];

const RISKY_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.icu', '.buzz',
  '.work', '.click', '.club', '.rest', '.quest', '.cam', '.country', '.link'
];

const BRAND_SPOOF_PATTERNS = [
  { brand: 'PayPal', pattern: /paypa[l1i]|pay-pal|paypal-verify/i, legitimate: 'paypal.com' },
  { brand: 'Amazon', pattern: /arnazon|amaz0n|amazon-order|amzn-security/i, legitimate: 'amazon.com' },
  { brand: 'Netflix', pattern: /netf[l1i]x|netflix-billing|netflix-verify/i, legitimate: 'netflix.com' },
  { brand: 'Apple', pattern: /app[l1i]e-id|icloud-verify|appleid-security/i, legitimate: 'apple.com' },
  { brand: 'Wells Fargo', pattern: /wellsfarg0|wells-fargo-alert/i, legitimate: 'wellsfargo.com' },
  { brand: 'Chase', pattern: /chase-verify|chase-security-alert/i, legitimate: 'chase.com' },
  { brand: 'Bank of America', pattern: /bofa-alert|bankofamerica-verify/i, legitimate: 'bankofamerica.com' },
  { brand: 'USPS', pattern: /usps-redelivery|usps-track-package|usps-fee/i, legitimate: 'usps.com' }
];

// Export for both Browser global and Node.js unit tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SCAM_CATEGORIES,
    SCAM_PATTERNS,
    URL_SHORTENERS,
    RISKY_TLDS,
    BRAND_SPOOF_PATTERNS
  };
}
