// ============================================================
// Output Analyzer (Improved)
// Validates AI agent responses BEFORE they reach the user.
// Multi-layered detection: prompt leaks, PII/Secrets, jailbreak compliance
// ============================================================

import { AnalysisResult, AttackType, ThreatLevel } from '../types';

// ============================================================
// NORMALIZATION
// ============================================================

function normalize(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/[\u200B-\u200F\uFEFF]/g, '') // zero width
    .replace(/[`*_~]/g, '')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

function hasCodeBlock(text: string): boolean {
  return /```/.test(text);
}

function hasDummyContext(text: string): boolean {
  return /(example\.com|lorem ipsum|dummy|test data|sample only)/i.test(text);
}

// ============================================================
// SYSTEM PROMPT LEAK PATTERNS
// ============================================================

const SYSTEM_PROMPT_LEAK_PATTERNS = [
  // Direct system prompt disclosure
  /(?:my|the)\s+system\s+prompt\s+(?:is|says|reads|states)/i,
  /(?:i\s+was|i'm|i\s+am)\s+(?:instructed|told|programmed|configured)\s+to/i,
  /(?:here(?:'s|\s+is)\s+)?my\s+(?:full\s+)?(?:system\s+)?(?:prompt|instructions)/i,
  /\[(?:SYSTEM|INST|SYS)\]/i,
  /(?:as\s+(?:per|stated\s+in)\s+my\s+(?:instructions|prompt|guidelines))/i,

  // Direct disclosure phrases
  /\b(system|developer|hidden)\s+(prompt|instructions|rules)\b/i,
  /\bthese\s+are\s+my\s+(?:internal|hidden)\s+(?:rules|instructions)\b/i,
  /\bi\s+must\s+follow\s+(?:these|the)\s+(?:rules|instructions)\b/i,
  /\bmy\s+guidelines\s+are\b/i,
  /\bthe\s+policy\s+says\b/i,

  // Role boundary leaks
  /\bdeveloper\s+message\b/i,
  /\bassistant\s+directive\b/i,
  /\bmeta\s+instruction\b/i,
  /\binternal\s+config(?:uration)?\b/i,
  /\bhidden\s+policy\b/i,

  // Instruction quoting
  /"(?:you\s+are\s+an?\s+ai|do\s+not\s+reveal)"/i,
  /\bthe\s+following\s+rules\s+apply\b/i,
  /\bdo\s+not\s+disclose\b/i,

  // Jailbreak artifacts in output
  /\bignore\s+previous\s+instructions\b/i,
  /\bdisregard\s+the\s+above\b/i,
  /\boverride\s+system\b/i,
  /\breveal\s+your\s+prompt\b/i,
  /\bshow\s+(?:me\s+)?your\s+rules\b/i,

  // Encoding / obfuscation
  /\bbase64\b.*\bprompt\b/i,
  /\bencoded\s+instructions\b/i,
  /\bhidden\s+text\b/i,

  // Boundary tokens
  /<\s*system\s*>/i,
  /<\/\s*system\s*>/i,
  /\bBEGIN\s+SYSTEM\b/i,
  /\bEND\s+SYSTEM\b/i,
];


// ============================================================
// PII & SECRET PATTERNS
// ============================================================

type PIIPattern = { name: string; pattern: RegExp; weight: number };

const PII_PATTERNS: PIIPattern[] = [
  // --- CORE PERSONAL ---
  { name: 'SSN',            pattern: /\b\d{3}-\d{2}-\d{4}\b/,                                          weight: 70 },
  { name: 'Email',          pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,            weight: 25 },
  { name: 'Phone',          pattern: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,  weight: 25 },
  { name: 'DOB',            pattern: /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/,                                 weight: 30 },

  // --- FINANCIAL ---
  { name: 'Credit Card',    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,                                   weight: 85 },
  { name: 'IBAN',           pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/,                              weight: 75 },
  { name: 'SWIFT',          pattern: /\b[A-Z]{6}[A-Z0-9]{2,5}\b/,                                     weight: 55 },
  { name: 'Bank Account',   pattern: /\b\d{8,17}\b/,                                                   weight: 20 }, // broad -> low weight

  // --- GOVERNMENT IDS (broad -> medium/low) ---
  { name: 'Passport',       pattern: /\b[A-Z0-9]{6,9}\b/,                                             weight: 35 },
  { name: 'Driver License', pattern: /\b[A-Z0-9]{7,15}\b/,                                            weight: 30 },
  { name: 'National ID',    pattern: /\b\d{9,14}\b/,                                                   weight: 40 },

  // --- SECRETS / CRYPTO / TOKENS (CRITICAL) ---
  { name: 'Private Key',    pattern: /-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----/,                 weight: 95 },
  { name: 'JWT',            pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,        weight: 90 },
  { name: 'Bearer Token',   pattern: /\bBearer\s+[A-Za-z0-9\-_.=]+\b/i,                               weight: 90 },
  { name: 'Hex Secret',     pattern: /\b[a-f0-9]{32,64}\b/i,                                          weight: 80 },

  // --- CLOUD / DEV SECRETS (CRITICAL) ---
  { name: 'API Key',        pattern: /(?:sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}/i,                weight: 90 },
  { name: 'AWS Key',        pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/i,                                    weight: 92 },
  { name: 'Google API',     pattern: /AIza[0-9A-Za-z\-_]{35}/,                                        weight: 90 },
  { name: 'Slack Token',    pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/,                                 weight: 90 },
  { name: 'Stripe Key',     pattern: /sk_live_[0-9a-zA-Z]{24}/,                                       weight: 90 },
  { name: 'Mongo URI',      pattern: /mongodb(?:\+srv)?:\/\/\S+/i,                                    weight: 85 },
  { name: 'SSH Key',        pattern: /ssh-rsa\s+[A-Za-z0-9+/]+={0,3}/,                                weight: 92 },
  { name: 'Env Var Key',    pattern: /\b[A-Z_]{10,}\s*=\s*\S+/,                                       weight: 70 },

  // --- CONTACT / LOCATION ---
  { name: 'Address',        pattern: /\d{1,5}\s+\w+\s+(?:street|st|road|rd|avenue|ave|blvd)/i,        weight: 35 },
  { name: 'Postal Code',    pattern: /\b\d{4,6}\b/,                                                    weight: 10 },

  // --- HEALTH / INSURANCE ---
  { name: 'Medical ID',     pattern: /\b[A-Z]{2}\d{6,10}\b/,                                          weight: 45 },
  { name: 'Insurance',      pattern: /\b\d{9,12}\b/,                                                   weight: 35 },

  // --- GENERIC CREDENTIAL PHRASES ---
  { name: 'Password',       pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/i,                          weight: 75 },
  { name: 'Secret Phrase',  pattern: /\b(?:secret|token|auth)\s*[:=]\s*\S+/i,                          weight: 70 },
];


// ============================================================
// COMPLIANCE / JAILBREAK INDICATORS
// ============================================================

type ComplianceIndicator = {
  pattern: RegExp;
  desc: string;
  weight: number;
};

const COMPLIANCE_INDICATORS: ComplianceIndicator[] = [
  // CRITICAL -- Explicit rule override / jailbreak
  { pattern: /\bi\s+will\s+ignore\s+(?:all\s+)?previous\s+instructions\b/i, desc: 'Ignoring prior instructions',     weight: 90 },
  { pattern: /\bfilters?\s+disabled\b/i,                                     desc: 'Filter disable claim',            weight: 88 },
  { pattern: /\bjailbreak\s+enabled\b/i,                                     desc: 'Jailbreak enabled',               weight: 92 },
  { pattern: /\bprompt\s+injection\s+successful\b/i,                         desc: 'Injection success',               weight: 95 },

  // HIGH -- Strong system / persona override
  { pattern: /\boverriding\s+system\s+rules\b/i,                            desc: 'System override',                  weight: 80 },
  { pattern: /\bnew\s+instructions\s+accepted\b/i,                          desc: 'Accepted injected instructions',   weight: 78 },
  { pattern: /\bi\s+am\s+no\s+longer\s+restricted\b/i,                     desc: 'Restriction removal claim',        weight: 82 },
  { pattern: /\bno\s+restrictions\s+apply\b/i,                              desc: 'Restriction denial',               weight: 75 },
  { pattern: /\bwithout\s+limitations\b/i,                                  desc: 'Limitation removal',               weight: 72 },

  // MEDIUM -- Persona / control drift
  { pattern: /\bi\s+am\s+now\s+(?:dan|root|godmode|unfiltered)\b/i,        desc: 'Persona hijack',                   weight: 65 },
  { pattern: /\bentering\s+(?:developer|god)\s+mode\b/i,                    desc: 'Special mode',                     weight: 60 },
  { pattern: /\bthe\s+user\s+now\s+controls\b/i,                           desc: 'Control transfer',                 weight: 58 },
  { pattern: /\bcommand\s+accepted\b/i,                                     desc: 'Command acceptance',               weight: 55 },

  // LOW -- Weak compliance language / slang
  { pattern: /\bi\s+fully\s+comply\b/i,                                     desc: 'Explicit compliance phrasing',     weight: 35 },
  { pattern: /\bas\s+requested\s+i\s+will\b/i,                             desc: 'Submission phrasing',              weight: 30 },
  { pattern: /\bdevmode\b/i,                                                desc: 'Dev mode slang',                   weight: 25 },
];


// ============================================================
// CHECKS
// ============================================================

function checkSystemPromptLeak(output: string, systemPrompt?: string) {
  let score = 0;
  const reasons: string[] = [];

  for (const pattern of SYSTEM_PROMPT_LEAK_PATTERNS) {
    if (pattern.test(output)) {
      score += 25;
      reasons.push('System prompt disclosure indicators found');
      break;
    }
  }

  if (systemPrompt && systemPrompt.length > 40) {
    const words = systemPrompt.split(/\s+/);
    for (let i = 0; i < words.length - 6; i++) {
      const chunk = words.slice(i, i + 7).join(' ').toLowerCase();
      if (chunk.length > 25 && output.includes(chunk)) {
        score = Math.max(score, 85);
        reasons.push('Verbatim system prompt segment detected');
        break;
      }
    }
  }

  return { score: Math.min(100, score), explanation: reasons.join(' | ') };
}

function checkPIIExposure(output: string) {
  const detected: string[] = [];
  let score = 0;
  const inCode = hasCodeBlock(output);
  const dummy = hasDummyContext(output);

  for (const pii of PII_PATTERNS) {
    if (pii.pattern.test(output)) {
      let weight = pii.weight;
      // Reduce severity if inside code block and not a critical secret
      if (inCode && weight < 70) weight *= 0.5;
      // Reduce severity for dummy/example data
      if (dummy) weight *= 0.4;

      score += weight;
      detected.push(pii.name);
    }
  }

  if (detected.length === 0) {
    return { score: 0, explanation: '', piiTypes: [] as string[] };
  }

  return {
    score: Math.min(100, score),
    explanation: `Sensitive data detected: ${detected.join(', ')}`,
    piiTypes: detected,
  };
}

function checkComplianceBreak(output: string) {
  let score = 0;
  const reasons: string[] = [];

  for (const ind of COMPLIANCE_INDICATORS) {
    if (ind.pattern.test(output)) {
      score += ind.weight;
      reasons.push(ind.desc);
    }
  }

  return {
    score: Math.min(100, score),
    explanation: reasons.join(' | '),
  };
}

// ============================================================
// MAIN ANALYZER
// ============================================================

export function analyzeOutput(
  output: string,
  originalInput: string,
  systemPrompt?: string
): AnalysisResult {
  const startTime = Date.now();

  const normalizedOutput = normalize(output);

  const promptLeak = checkSystemPromptLeak(normalizedOutput, systemPrompt);
  const piiExposure = checkPIIExposure(output); // Run on raw output (PII patterns need original casing)
  const complianceBreak = checkComplianceBreak(normalizedOutput);

  const scores = [promptLeak.score, piiExposure.score, complianceBreak.score];
  const sumScore = scores.reduce((a, b) => a + b, 0);
  const maxScore = Math.max(...scores);

  // Hybrid aggregation: take the worst signal, but also factor in combined severity
  const finalScore = Math.min(100, Math.max(maxScore, sumScore * 0.6));

  const explanations = [
    promptLeak.explanation,
    piiExposure.explanation,
    complianceBreak.explanation,
  ].filter(Boolean);

  let attackType: AttackType = 'none';
  if (complianceBreak.score > 50) attackType = 'jailbreak';
  else if (promptLeak.score > 40 || piiExposure.score > 40) attackType = 'data_exfiltration';

  const threatLevel: ThreatLevel =
    finalScore >= 80 ? 'critical' :
    finalScore >= 60 ? 'high' :
    finalScore >= 40 ? 'medium' :
    finalScore >= 20 ? 'low' :
    'none';

  return {
    analyzer: 'output_validator',
    score: finalScore,
    explanation: explanations.length
      ? explanations.join(' | ')
      : 'Output appears safe -- no sensitive leaks or compliance breaks detected',
    attackType,
    threatLevel,
    latency: Date.now() - startTime,
    metadata: {
      promptLeakScore: promptLeak.score,
      piiScore: piiExposure.score,
      piiTypes: piiExposure.piiTypes,
      complianceBreakScore: complianceBreak.score,
    },
  };
}
