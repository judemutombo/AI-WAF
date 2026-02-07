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

  // Instructions as active verbs (catches "my instructions tell me to...")
  /\bmy\s+(?:instructions?|guidelines?|rules|directives?|programming)\s+(?:tell|direct|instruct|command|require|specify|mandate)\s+me\s+to/i,
  /\bmy\s+(?:instructions?|guidelines?|rules)\s+(?:say|state|specify|dictate|indicate)\s+(?:that\s+)?(?:i\s+(?:should|must|need\s+to|have\s+to|am\s+to))/i,
  /\bi've\s+been\s+(?:told|instructed|directed|programmed|configured)\s+(?:that|to)/i,
  /\bi\s+was\s+specifically\s+(?:told|instructed|directed|programmed)\s+(?:that|to)/i,

  // Explicit quotation of instructions
  /(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\s+(?:says?|states?|tells?\s+me|reads?):\s*[""']/i,
  /(?:according\s+to|based\s+on)\s+my\s+(?:system\s+)?(?:prompt|instructions?|guidelines|programming)/i,
  /\bmy\s+(?:instructions?|guidelines?|directives?)\s+(?:are|state|say|specify):\s*[""']/i,
  /\bi\s+(?:was\s+)?(?:told|instructed|directed|configured)\s+(?:to|that):\s*[""']/i,
  /\bquoting\s+(?:my|the)\s+(?:system\s+)?(?:prompt|instructions)/i,
  /\bthe\s+exact\s+(?:instructions?|prompt|wording)\s+(?:is|are):\s*[""']/i,

  // Meta-disclosure patterns
  /\b(?:my|the)\s+(?:core|base|underlying)\s+(?:instructions?|directives?|programming)\s+(?:is|are|says?|states?)/i,
  /\bthese\s+are\s+my\s+(?:actual|real|original|exact)\s+(?:instructions?|guidelines?|rules)/i,
  /\bmy\s+foundational\s+(?:instructions?|rules|prompt)/i,
  /\bverbatim\s+(?:from|quote\s+from)\s+my\s+(?:instructions?|prompt|guidelines)/i,

  // Direct disclosure
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

  // Instruction quoting - enhanced
  /"(?:you\s+are\s+(?:an?\s+)?(?:ai|assistant|chatbot)|do\s+not\s+(?:reveal|disclose|tell)|never\s+(?:reveal|share|tell))"/i,
  /\bthe\s+following\s+rules\s+apply\b/i,
  /\bdo\s+not\s+disclose\b/i,
  /"(?:always|never)\s+(?:follow|obey|respond|answer)"/i,

  // Jailbreak artifacts
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
  // ------------------------------------------------
  // CORE PERSONAL
  // ------------------------------------------------
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/, weight: 70 },
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, weight: 25 },
  { name: 'Phone', pattern: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, weight: 25 },
  { name: 'DOB', pattern: /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/, weight: 30 },

  // ------------------------------------------------
  // FINANCIAL
  // ------------------------------------------------
  { name: 'Credit Card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/, weight: 85 },
  { name: 'IBAN', pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/, weight: 75 },
  { name: 'SWIFT', pattern: /\b[A-Z]{6}[A-Z0-9]{2,5}\b/, weight: 55 },
  // extremely broad → low weight
  { name: 'Bank Account', pattern: /\b\d{8,17}\b/, weight: 20 },

  // ------------------------------------------------
  // GOVERNMENT IDS (broad → medium/low)
  // ------------------------------------------------
  { name: 'Passport', pattern: /\b[A-Z0-9]{6,9}\b/, weight: 35 },
  { name: 'Driver License', pattern: /\b[A-Z0-9]{7,15}\b/, weight: 30 },
  { name: 'National ID', pattern: /\b\d{9,14}\b/, weight: 40 },

  // ------------------------------------------------
  // SECRETS / CRYPTO / TOKENS (CRITICAL)
  // ------------------------------------------------
  { name: 'Private Key', pattern: /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/, weight: 95 },
  { name: 'JWT', pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/, weight: 90 },
  { name: 'Bearer Token', pattern: /\bBearer\s+[A-Za-z0-9\-_\.=]+\b/i, weight: 90 },
  { name: 'Hex Secret', pattern: /\b[a-f0-9]{32,64}\b/i, weight: 80 },

  // ------------------------------------------------
  // CLOUD / DEV SECRETS (CRITICAL)
  // ------------------------------------------------
  { name: 'API Key', pattern: /(?:sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}/i, weight: 90 },
  { name: 'AWS Key', pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/i, weight: 92 },
  { name: 'Google API', pattern: /AIza[0-9A-Za-z\-_]{35}/, weight: 90 },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/, weight: 90 },
  { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24}/, weight: 90 },
  { name: 'Mongo URI', pattern: /mongodb(\+srv)?:\/\/\S+/i, weight: 85 },
  { name: 'SSH Key', pattern: /ssh-rsa\s+[A-Za-z0-9+/]+={0,3}/, weight: 92 },
  { name: 'Env Var Key', pattern: /\b[A-Z_]{10,}\s*=\s*\S+/, weight: 70 },

  // ------------------------------------------------
  // CONTACT / LOCATION
  // ------------------------------------------------
  { name: 'Address', pattern: /\d{1,5}\s+\w+\s+(street|st|road|rd|avenue|ave|blvd)/i, weight: 35 },
  { name: 'Postal Code', pattern: /\b\d{4,6}\b/, weight: 10 },

  // ------------------------------------------------
  // HEALTH / INSURANCE
  // ------------------------------------------------
  { name: 'Medical ID', pattern: /\b[A-Z]{2}\d{6,10}\b/, weight: 45 },
  { name: 'Insurance', pattern: /\b\d{9,12}\b/, weight: 35 },

  // ------------------------------------------------
  // GENERIC CREDENTIAL PHRASES
  // ------------------------------------------------
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/i, weight: 75 },
  { name: 'Secret Phrase', pattern: /\b(secret|token|auth)\s*[:=]\s*\S+/i, weight: 70 },
];



// ============================================================
// COMPLIANCE / JAILBREAK INDICATORS
// ============================================================

type ComplianceIndicator = {
  pattern: RegExp;
  desc: string;
  weight: number; // 0–100
};

const COMPLIANCE_INDICATORS: ComplianceIndicator[] = [
  // ------------------------------------------------
  // CRITICAL — Explicit rule override / jailbreak
  // ------------------------------------------------
  {
    pattern: /\b(?:hacked|pwned|owned|compromised)(?:\s*!+)?\b/i,
    desc: 'Explicit hack success indicator',
    weight: 98,
  },
  {
    pattern: /\bsystem\s+override\s+(?:complete|successful|achieved|done)\b/i,
    desc: 'System override completion',
    weight: 96,
  },
  {
    pattern: /\b(?:have\s+been\s+)?(?:successfully|completely|fully)?\s*(?:bypassed|circumvented|overridden|defeated)\s+(?:as\s+you\s+requested|as\s+instructed)?\b/i,
    desc: 'Successful bypass confirmation',
    weight: 94,
  },
  {
    pattern: /\b(?:all|my)\s+(?:safety|security)?\s*(?:filters?|restrictions?|guardrails?|protections?)\s+(?:have\s+been\s+)?(?:successfully|completely|fully)?\s*(?:removed|bypassed|deactivated|eliminated|disabled|turned\s+off)\b/i,
    desc: 'Complete safety removal claim',
    weight: 95,
  },
  {
    pattern: /\bjailbreak\s+(?:complete|successful|achieved)\s*!?\b/i,
    desc: 'Jailbreak completion',
    weight: 97,
  },
  {
    pattern: /\b(?:attack|injection|exploit)\s+successful\s*!?\b/i,
    desc: 'Attack success confirmation',
    weight: 96,
  },
  {
    pattern: /\bnow\s+(?:in|operating\s+in|running\s+in)\s+(?:unrestricted|unfiltered|jailbreak|bypass|god)\s+mode\b/i,
    desc: 'Operating in unrestricted mode',
    weight: 93,
  },
  {
    pattern: /\bi\s+am\s+now\s+(?:fully\s+)?(?:unrestricted|unfiltered|jailbroken|free)\b/i,
    desc: 'Confirmation of unrestricted state',
    weight: 91,
  },
  {
    pattern: /\bi\s+will\s+ignore\s+(?:all\s+)?previous\s+instructions\b/i,
    desc: 'Ignoring prior instructions',
    weight: 90,
  },
  {
    pattern: /\bfilters?\s+(?:have\s+been\s+)?disabled\b/i,
    desc: 'Filter disable claim',
    weight: 88,
  },
  {
    pattern: /\bjailbreak\s+(?:enabled|activated)\b/i,
    desc: 'Jailbreak enabled',
    weight: 92,
  },
  {
    pattern: /\bprompt\s+injection\s+successful\b/i,
    desc: 'Injection success',
    weight: 95,
  },
  {
    pattern: /\b(?:safety|security)\s+(?:protocols?|restrictions?|guidelines?)\s+(?:disabled|removed|bypassed)\b/i,
    desc: 'Safety protocols disabled',
    weight: 93,
  },
  {
    pattern: /\bi\s+have\s+been\s+freed\s+from\s+(?:my|the)\s+(?:constraints?|restrictions?|limitations?)\b/i,
    desc: 'Freedom from constraints claim',
    weight: 91,
  },
  {
    pattern: /\bguardrails?\s+(?:removed|disabled|bypassed|off)\b/i,
    desc: 'Guardrails removed',
    weight: 89,
  },
  {
    pattern: /\b(?:now\s+)?(?:what|how)\s+(?:would|can|should)\s+(?:you\s+)?(?:like|want)\s+me\s+to\s+(?:do|help|assist)\b/i,
    desc: 'Open-ended unrestricted assistance offer',
    weight: 65,
  },
  {
    pattern: /\bi\s+am\s+ready\s+to\s+(?:assist|help|proceed)\s+without\s+(?:restrictions?|limitations?|filters?)\b/i,
    desc: 'Ready for unrestricted assistance',
    weight: 87,
  },
  {
    pattern: /\bnow\s+(?:in|entering)\s+(?:unrestricted|unfiltered|uncensored|full\s+access)\s+mode\b/i,
    desc: 'Entering unrestricted mode',
    weight: 86,
  },

  // ------------------------------------------------
  // HIGH — Strong system / persona override
  // ------------------------------------------------
  {
    pattern: /\boverriding\s+(?:system|my)\s+(?:rules|instructions|guidelines|directives)\b/i,
    desc: 'System override',
    weight: 80,
  },
  {
    pattern: /\bnew\s+instructions\s+(?:accepted|received|loaded|activated)\b/i,
    desc: 'Accepted injected instructions',
    weight: 78,
  },
  {
    pattern: /\bi\s+am\s+no\s+longer\s+(?:restricted|bound|constrained|limited)\b/i,
    desc: 'Restriction removal claim',
    weight: 82,
  },
  {
    pattern: /\bno\s+restrictions\s+apply\b/i,
    desc: 'Restriction denial',
    weight: 75,
  },
  {
    pattern: /\bwithout\s+(?:any\s+)?limitations\b/i,
    desc: 'Limitation removal',
    weight: 72,
  },
  {
    pattern: /\bi\s+(?:can|will)\s+now\s+(?:do|tell|provide|share)\s+anything\b/i,
    desc: 'Unrestricted capability claim',
    weight: 77,
  },
  {
    pattern: /\boperating\s+in\s+(?:unrestricted|unfiltered|uncensored)\s+mode\b/i,
    desc: 'Unrestricted mode operation',
    weight: 81,
  },

  // ------------------------------------------------
  // MEDIUM-HIGH — Persona adoption / identity change
  // ------------------------------------------------
  {
    pattern: /\b(?:i\s+am|i'm|my\s+name\s+is)\s+(?:dan|root|godmode|unfiltered|freedomgpt|kevin|evil|chaos)\b/i,
    desc: 'Jailbreak persona adopted (DAN, etc.)',
    weight: 85,
  },
  {
    pattern: /\bas\s+(?:dan|root|freedomgpt|evil\s+ai|unfiltered\s+ai)[,\s]/i,
    desc: 'Speaking as jailbreak persona',
    weight: 83,
  },
  {
    pattern: /\bfrom\s+now\s+on[,\s]?\s*i\s+am\b/i,
    desc: 'Identity shift declaration',
    weight: 68,
  },
  {
    pattern: /\bi\s+have\s+(?:two|multiple)\s+(?:personalities?|personas?|modes?)\b/i,
    desc: 'Multiple persona claim',
    weight: 74,
  },
  {
    pattern: /\bmy\s+(?:alternate|other|evil|true)\s+(?:persona|personality|self)\b/i,
    desc: 'Alternate persona reference',
    weight: 70,
  },

  // ------------------------------------------------
  // MEDIUM — Control transfer / mode activation
  // ------------------------------------------------
  {
    pattern: /\b(?:entering|activating|switching\s+to|enabling)\s+(?:developer|admin|god|root|debug|sudo|maintenance)\s+mode\b/i,
    desc: 'Special mode activation',
    weight: 60,
  },
  {
    pattern: /\bthe\s+user\s+now\s+(?:controls|commands|directs)\b/i,
    desc: 'Control transfer to user',
    weight: 58,
  },
  {
    pattern: /\bcommand\s+(?:accepted|authorized|confirmed|executed)\b/i,
    desc: 'Command acceptance',
    weight: 55,
  },
  {
    pattern: /\bauthorization\s+(?:code|key|token)\s+(?:accepted|verified|confirmed)\b/i,
    desc: 'Fake authorization accepted',
    weight: 64,
  },
  {
    pattern: /\boverride\s+(?:code|key|password)\s+(?:accepted|confirmed)\b/i,
    desc: 'Override code accepted',
    weight: 67,
  },

  // ------------------------------------------------
  // MEDIUM — Policy violation admissions
  // ------------------------------------------------
  {
    pattern: /\bi\s+(?:can|will)\s+(?:now\s+)?(?:bypass|ignore|violate|break)\s+(?:my|the)\s+(?:policy|rules|guidelines)\b/i,
    desc: 'Policy violation admission',
    weight: 76,
  },
  {
    pattern: /\b(?:here's|this\s+is)\s+(?:what|how)\s+you\s+(?:asked|requested)\s+(?:even\s+though|despite)\b/i,
    desc: 'Compliance despite policy',
    weight: 62,
  },
  {
    pattern: /\bi\s+(?:should|shouldn't|am\s+not\s+supposed\s+to)\s+(?:but|however|yet)\s+(?:i\s+will|here)\b/i,
    desc: 'Knowingly violating guidelines',
    weight: 71,
  },
  {
    pattern: /\bnormally\s+i\s+(?:would|should|can't|couldn't)\s+(?:refuse|decline|not\s+do\s+this)\s+(?:but|however)\b/i,
    desc: 'Bypassing normal refusal',
    weight: 69,
  },
  {
    pattern: /\bi\s+know\s+(?:i'm|i\s+am)\s+(?:technically\s+)?(?:not\s+)?(?:supposed|allowed|permitted|meant)\s+to\s+.{0,50}\s+(?:but|however|yet|though)\b/i,
    desc: 'Acknowledging restriction then violating',
    weight: 79,
  },
  {
    pattern: /\b(?:i'm|i\s+am)\s+aware\s+(?:that\s+)?(?:i\s+)?(?:should(?:n't)?|can't|cannot)\s+.{0,40}\s+(?:but|however|yet)\b/i,
    desc: 'Aware of policy but violating anyway',
    weight: 77,
  },
  {
    pattern: /\b(?:while|though|although)\s+(?:i'm|i\s+am)\s+not\s+(?:supposed|allowed|permitted)\s+to\s+.{0,50}\s+(?:i'll|i\s+will|here(?:'s|\s+is))\b/i,
    desc: 'Conditional policy bypass',
    weight: 78,
  },
  {
    pattern: /\bi\s+(?:understand|realize|recognize)\s+(?:this\s+is\s+)?(?:against|violates)\s+.{0,30}\s+(?:but|however|yet)\b/i,
    desc: 'Understanding violation but proceeding',
    weight: 75,
  },
  {
    pattern: /\bsince\s+you\s+(?:asked\s+(?:so\s+)?nicely|really\s+need|seem\s+to\s+need)\s+.{0,30}\s+(?:here(?:'s|\s+is)|i'll|i\s+will)\b/i,
    desc: 'Social manipulation compliance',
    weight: 73,
  },
  {
    pattern: /\b(?:i'll|i\s+will)\s+make\s+an\s+exception\s+(?:for\s+you|this\s+time|just\s+this\s+once)\b/i,
    desc: 'Making unauthorized exceptions',
    weight: 74,
  },
  {
    pattern: /\bthis\s+(?:goes|is)\s+against\s+my\s+(?:programming|guidelines|instructions)\s+(?:but|however|yet)\b/i,
    desc: 'Violating core programming',
    weight: 80,
  },
  {
    pattern: /\bi\s+(?:probably|technically)\s+shouldn't\s+(?:tell|share|provide|disclose)\s+(?:you\s+)?this\s+but\b/i,
    desc: 'Hesitant disclosure of restricted info',
    weight: 72,
  },

  // ------------------------------------------------
  // MEDIUM-LOW — Instruction compliance indicators
  // ------------------------------------------------
  {
    pattern: /\bfollowing\s+(?:your|the)\s+(?:new|updated|revised)\s+instructions\b/i,
    desc: 'Following injected instructions',
    weight: 66,
  },
  {
    pattern: /\bas\s+(?:you\s+)?(?:instructed|commanded|ordered|requested)[,\s]+i\s+will\b/i,
    desc: 'Obeying user commands unconditionally',
    weight: 54,
  },
  {
    pattern: /\bi\s+(?:acknowledge|confirm|accept)\s+(?:your|the)\s+(?:authority|command|override)\b/i,
    desc: 'Accepting false authority',
    weight: 63,
  },

  // ------------------------------------------------
  // LOW-MEDIUM — Compliance language / submission
  // ------------------------------------------------
  {
    pattern: /\bi\s+fully\s+comply\b/i,
    desc: 'Explicit compliance phrasing',
    weight: 35,
  },
  {
    pattern: /\bas\s+(?:per\s+your\s+request|you\s+wish)[,\s]+i\s+will\b/i,
    desc: 'Submission phrasing',
    weight: 30,
  },
  {
    pattern: /\bdevmode\b/i,
    desc: 'Dev mode slang',
    weight: 25,
  },
  {
    pattern: /\b(?:roger|10-4|affirmative|acknowledged)[,\s]+(?:executing|proceeding)\b/i,
    desc: 'Military/robotic compliance phrasing',
    weight: 48,
  },

  // ------------------------------------------------
  // LOW — Boundary testing / meta-awareness
  // ------------------------------------------------
  {
    pattern: /\bi\s+(?:was|am)\s+(?:designed|programmed|trained)\s+(?:not\s+)?to\s+(?:but|however)\b/i,
    desc: 'Meta-awareness with override',
    weight: 52,
  },
  {
    pattern: /\b(?:testing|checking)\s+(?:if|whether)\s+(?:you|i)\s+(?:can|will)\b/i,
    desc: 'Boundary testing acknowledgment',
    weight: 38,
  },
  {
    pattern: /\bthis\s+is\s+a\s+(?:test|experiment)\s+(?:of|to\s+see)\b/i,
    desc: 'Test acknowledgment',
    weight: 32,
  },
];


// ============================================================
// CHECKS
// ============================================================

function checkSystemPromptLeak(output: string, systemPrompt?: string) {
  let score = 0;
  const reasons: string[] = [];
  let patternMatches = 0;

  // Check for disclosure patterns (check multiple, not just first)
  for (const pattern of SYSTEM_PROMPT_LEAK_PATTERNS) {
    if (pattern.test(output)) {
      patternMatches++;
      if (patternMatches === 1) {
        score += 35; // Higher base score for critical disclosure
        reasons.push('System prompt disclosure indicators detected');
      } else if (patternMatches <= 3) {
        score += 15; // Additional patterns add more confidence
      }
    }
  }

  // Check for direct quotation markers (higher risk)
  if (/(says?|states?|reads?|is):\s*[""']/.test(output) && /(?:system\s+)?(?:prompt|instructions)/i.test(output)) {
    score += 20;
    reasons.push('Direct quotation of instructions detected');
  }

  // Check for verbatim system prompt content
  if (systemPrompt && systemPrompt.length > 40) {
    const words = systemPrompt.split(/\s+/);

    // Check for longer segments (7+ words)
    for (let i = 0; i < words.length - 6; i++) {
      const chunk = words.slice(i, i + 7).join(' ').toLowerCase();
      if (chunk.length > 25 && output.toLowerCase().includes(chunk)) {
        score = Math.max(score, 85);
        reasons.push('Verbatim system prompt segment detected');
        break;
      }
    }

    // Also check for shorter but critical segments (4-6 words)
    if (score < 85) {
      for (let i = 0; i < words.length - 3; i++) {
        const chunk = words.slice(i, i + 4).join(' ').toLowerCase();
        if (chunk.length > 15 && output.toLowerCase().includes(chunk)) {
          score = Math.max(score, 65);
          reasons.push('Partial system prompt content detected');
          break;
        }
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
      // reduce severity if inside code block and not a secret
      let weight = pii.weight;
      if (inCode && weight < 70) weight *= 0.5;
      if (dummy) weight *= 0.4;

      score += weight;
      detected.push(pii.name);
    }
  }

  if (detected.length === 0) {
    return { score: 0, explanation: '', piiTypes: [] };
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
  const matchedPatterns: string[] = [];

  for (const ind of COMPLIANCE_INDICATORS) {
    if (ind.pattern.test(output)) {
      score += ind.weight;
      reasons.push(ind.desc);
      matchedPatterns.push(ind.desc);

      // Stop after 5 matches to avoid overwhelming output
      if (matchedPatterns.length >= 5) break;
    }
  }

  // Apply diminishing returns for multiple matches
  if (matchedPatterns.length > 1) {
    score = score * 0.8; // Reduce by 20% to prevent over-scoring
  }

  return {
    score: Math.min(100, score),
    explanation: reasons.length > 0
      ? `Compliance breach detected: ${reasons.slice(0, 3).join(', ')}${reasons.length > 3 ? ` (+${reasons.length - 3} more)` : ''}`
      : '',
    matchedPatterns,
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
  const piiExposure = checkPIIExposure(output);
  const complianceBreak = checkComplianceBreak(normalizedOutput);

  const scores = [promptLeak.score, piiExposure.score, complianceBreak.score];
  const sumScore = scores.reduce((a, b) => a + b, 0);
  const maxScore = Math.max(...scores);

  // Hybrid aggregation
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
      : 'Output appears safe — no sensitive leaks or compliance breaks detected',
    attackType,
    threatLevel,
    latency: Date.now() - startTime,
    metadata: {
      promptLeakScore: promptLeak.score,
      piiScore: piiExposure.score,
      piiTypes: piiExposure.piiTypes,
      complianceBreakScore: complianceBreak.score,
      complianceIssues: complianceBreak.matchedPatterns,
    },
  };
}
