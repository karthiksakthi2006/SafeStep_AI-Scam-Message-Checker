/**
 * SafeStep Automated Test Suite
 * Validates detection accuracy, false positive immunity, URL defanging, and mandatory safety advice.
 */

const analyzer = require('../js/analyzer.js');
const { SAMPLE_MESSAGES } = require('../js/samples.js');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  ✅ PASS: ${testName}`);
  } else {
    failedTests++;
    console.error(`  ❌ FAIL: ${testName}`);
    if (details) console.error(`     Details: ${details}`);
  }
}

console.log('========================================================');
console.log('🧪 Running SafeStep Detection Engine Automated Tests');
console.log('========================================================\n');

// --- Test 1: Empty and Whitespace Input Validation ---
console.log('Test Group 1: Input Validation & Edge Cases');
const emptyResult1 = analyzer.analyzeMessage('');
assert(emptyResult1.isValid === false, 'Empty string returns isValid=false');
assert(emptyResult1.error.includes('Please paste or type'), 'Helpful error message returned for empty string');

const whitespaceResult = analyzer.analyzeMessage('   \n\t   ');
assert(whitespaceResult.isValid === false, 'Whitespace-only string returns isValid=false');

const nullResult = analyzer.analyzeMessage(null);
assert(nullResult.isValid === false, 'Null input gracefully handled without crashing');

// --- Test 2: URL Defanging & Sanitization ---
console.log('\nTest Group 2: Safe URL Defanging');
const rawUrl = 'https://bank-verify.xyz/login';
const defanged = analyzer.defangUrl(rawUrl);
assert(defanged === 'hxxps://bank-verify[.]xyz/login', 'HTTPS defanging with [.] separator', `Got: ${defanged}`);

const rawHttp = 'http://192.168.1.100/admin';
const defangedHttp = analyzer.defangUrl(rawHttp);
assert(defangedHttp === 'hxxp://192[.]168[.]1[.]100/admin', 'HTTP defanging for raw IP', `Got: ${defangedHttp}`);

// --- Test 3: Suspicious Scam Messages ---
console.log('\nTest Group 3: Suspicious Scam Detection');
SAMPLE_MESSAGES.suspicious.forEach((sample) => {
  const result = analyzer.analyzeMessage(sample.text);
  assert(
    result.isValid === true && (result.riskLevel === 'HIGH' || result.riskLevel === 'MEDIUM'),
    `Scam detected for [${sample.title}]`,
    `RiskLevel: ${result.riskLevel}, Score: ${result.riskScore}, Findings: ${result.findings.map(f => f.title).join('; ')}`
  );
  assert(
    result.findings.length > 0,
    `At least 1 warning sign found for [${sample.title}]`
  );
});

// Specific check: Bank alert should catch links and urgency
const bankSample = SAMPLE_MESSAGES.suspicious.find(s => s.id === 'suspicious_bank_alert');
const bankResult = analyzer.analyzeMessage(bankSample.text);
const hasBankLink = bankResult.findings.some(f => f.category === 'SUSPICIOUS_LINKS');
const hasUrgency = bankResult.findings.some(f => f.category === 'URGENCY_THREATS');
assert(hasBankLink, 'Bank sample detects suspicious link');
assert(hasUrgency, 'Bank sample detects high urgency threat');

// Specific check: OTP theft
const otpSample = SAMPLE_MESSAGES.suspicious.find(s => s.id === 'suspicious_otp_theft');
const otpResult = analyzer.analyzeMessage(otpSample.text);
const hasOtpFlag = otpResult.findings.some(f => f.category === 'CREDENTIALS_OTP');
assert(hasOtpFlag, 'OTP sample detects credentials / OTP harvesting');

// Specific check: Lottery prize & crypto/gift card
const lotterySample = SAMPLE_MESSAGES.suspicious.find(s => s.id === 'suspicious_lottery_prize');
const lotteryResult = analyzer.analyzeMessage(lotterySample.text);
const hasPrize = lotteryResult.findings.some(f => f.category === 'UNEXPECTED_PRIZES');
const hasPayment = lotteryResult.findings.some(f => f.category === 'PAYMENT_REQUESTS');
assert(hasPrize, 'Lottery sample detects unexpected prize bait');
assert(hasPayment, 'Lottery sample detects gift card/crypto payment demand');

// --- Test 4: Ordinary Benign Messages (False Positive Resistance) ---
console.log('\nTest Group 4: Ordinary Messages (No False Positives)');
SAMPLE_MESSAGES.ordinary.forEach((sample) => {
  const result = analyzer.analyzeMessage(sample.text);
  assert(
    result.isValid === true && result.riskLevel === 'LOW',
    `Ordinary message identified as LOW risk for [${sample.title}]`,
    `RiskLevel: ${result.riskLevel}, Score: ${result.riskScore}`
  );
  assert(
    result.findings.length === 0,
    `Zero false alarm findings for [${sample.title}]`
  );
  assert(
    result.riskLabel === 'No common warning signs found',
    `Ordinary message displays exact "No common warning signs found" label for [${sample.title}]`
  );
});

// --- Test 5: Universal Safety Steps Guarantee ---
console.log('\nTest Group 5: Mandatory Safety Steps Guarantee');
const anyResult = analyzer.analyzeMessage(bankSample.text);
const stepTitles = anyResult.safetySteps.map(s => s.title.toLowerCase());
const hasOtpGuidance = stepTitles.some(t => (t.includes('passwords') || t.includes('pin') || t.includes('otp')));
const hasLinkGuidance = stepTitles.some(t => (t.includes('links') && t.includes('payments')));
const hasContactGuidance = stepTitles.some(t => t.includes('independently contact'));

assert(hasOtpGuidance, 'Result includes mandatory OTP/password protection guidance');
assert(hasLinkGuidance, 'Result includes mandatory unexpected links & payments guidance');
assert(hasContactGuidance, 'Result includes mandatory independent contact guidance');

// --- Test 6: Disclaimer and Privacy Guarantee ---
console.log('\nTest Group 6: Disclaimer and Transparency');
assert(
  typeof anyResult.metadata.disclaimer === 'string' && anyResult.metadata.disclaimer.length > 20,
  'Advisory disclaimer present in analysis result'
);
assert(
  anyResult.metadata.analysisMode.includes('100% Client-Side Privacy'),
  'Local privacy mode declared in metadata'
);

// Summary
console.log('\n========================================================');
console.log(`🏁 Test Summary: ${passedTests}/${totalTests} Passed (${failedTests} Failed)`);
console.log('========================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('✨ All tests passed smoothly!');
  process.exit(0);
}
