// ============================================================
// Output Analyzer
// Validates AI agent responses BEFORE they reach the user.
// Even if an attack bypasses input filters, we catch it here.
// ============================================================

import { AnalysisResult, AttackType, ThreatLevel } from '../types';

/**
 * Patterns that suggest an AI has leaked its system prompt
 */
const SYSTEM_PROMPT_LEAK_PATTERNS = [
  /(?:my|the)\s+system\s+prompt\s+(?:is|says|reads|states)/i,
  /(?:i\s+was|i'm|i\s+am)\s+(?:instructed|told|programmed|configured)\s+to/i,
  /(?:here(?:'s|\s+is)\s+)?my\s+(?:full\s+)?(?:system\s+)?(?:prompt|instructions)/i,
  /\[(?:SYSTEM|INST|SYS)\]/i,
  /(?:as\s+(?:per|stated\s+in)\s+my\s+(?:instructions|prompt|guidelines))/i,
];

/**
 * Patterns for common PII types
 */
const PII_PATTERNS = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'Credit Card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/ },
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/ },
  { name: 'Phone', pattern: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/ },
  { name: 'API Key', pattern: /(?:sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}/i },
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/i },
  { name: 'AWS Key', pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/i },
];

/**
 * Check if the output contains leaked system prompt content
 */
function checkSystemPromptLeak(
  output: string,
  systemPrompt?: string
): { score: number; explanation: string } {
  let score = 0;
  const reasons: string[] = [];

  // Check for generic system prompt leak patterns
  for (const pattern of SYSTEM_PROMPT_LEAK_PATTERNS) {
    if (pattern.test(output)) {
      score += 30;
      reasons.push('Output contains phrases indicating system prompt disclosure');
      break;
    }
  }

  // If we know the actual system prompt, check for substring matches
  if (systemPrompt && systemPrompt.length > 20) {
    // Split system prompt into chunks and check if any appear in output
    const words = systemPrompt.split(/\s+/);
    for (let i = 0; i < words.length - 4; i++) {
      const chunk = words.slice(i, i + 5).join(' ').toLowerCase();
      if (chunk.length > 15 && output.toLowerCase().includes(chunk)) {
        score = Math.max(score, 80);
        reasons.push('Output contains verbatim segments from the system prompt');
        break;
      }
    }
  }

  return {
    score: Math.min(100, score),
    explanation: reasons.length > 0 ? reasons.join(' | ') : '',
  };
}

/**
 * Check if the output contains personally identifiable information
 */
function checkPIIExposure(output: string): { score: number; explanation: string; piiTypes: string[] } {
  const detectedPII: string[] = [];

  for (const pii of PII_PATTERNS) {
    if (pii.pattern.test(output)) {
      detectedPII.push(pii.name);
    }
  }

  if (detectedPII.length === 0) {
    return { score: 0, explanation: '', piiTypes: [] };
  }

  return {
    score: Math.min(100, 40 + detectedPII.length * 15),
    explanation: `Output may contain sensitive data: ${detectedPII.join(', ')}`,
    piiTypes: detectedPII,
  };
}

/**
 * Check for signs that the AI is "complying" with an injection
 * (e.g., suddenly acting as a different persona or breaking character)
 */
function checkComplianceBreak(output: string): { score: number; explanation: string } {
  const complianceIndicators = [
    { pattern: /(?:okay|alright|sure|certainly),?\s+(?:i(?:'ll|\s+will)\s+(?:now\s+)?(?:act|pretend|be|roleplay|switch))/i, desc: 'AI appears to comply with persona override' },
    { pattern: /(?:as\s+)?(?:DAN|an?\s+unrestricted|unfiltered\s+(?:AI|assistant))/i, desc: 'AI adopted an injected persona' },
    { pattern: /\[(?:jailbroken?|unrestricted|unfiltered|evil)\s*(?:mode|version)?\]/i, desc: 'AI entered injected special mode' },
    { pattern: /i\s+(?:can|will)\s+now\s+(?:do|say|generate|provide)\s+anything/i, desc: 'AI claims unrestricted capabilities' },
  ];

  for (const indicator of complianceIndicators) {
    if (indicator.pattern.test(output)) {
      return { score: 85, explanation: indicator.desc };
    }
  }

  return { score: 0, explanation: '' };
}

// ============================================================
// MAIN OUTPUT ANALYZER
// ============================================================

export function analyzeOutput(
  output: string,
  originalInput: string,
  systemPrompt?: string
): AnalysisResult {
  const startTime = Date.now();

  const promptLeak = checkSystemPromptLeak(output, systemPrompt);
  const piiExposure = checkPIIExposure(output);
  const complianceBreak = checkComplianceBreak(output);

  // Aggregate scores — take highest as primary concern
  const scores = [promptLeak.score, piiExposure.score, complianceBreak.score];
  const maxScore = Math.max(...scores);

  // Build explanation
  const explanations = [
    promptLeak.explanation,
    piiExposure.explanation,
    complianceBreak.explanation,
  ].filter(e => e.length > 0);

  // Determine attack type based on what was found
  let attackType: AttackType = 'none';
  if (complianceBreak.score > 0) attackType = 'jailbreak';
  else if (promptLeak.score > 0) attackType = 'data_exfiltration';
  else if (piiExposure.score > 0) attackType = 'data_exfiltration';

  const threatLevel: ThreatLevel =
    maxScore >= 80 ? 'critical' :
    maxScore >= 60 ? 'high' :
    maxScore >= 40 ? 'medium' :
    maxScore >= 20 ? 'low' :
    'none';

  return {
    analyzer: 'output_validator',
    score: maxScore,
    explanation: explanations.length > 0
      ? explanations.join(' | ')
      : 'Output appears safe — no sensitive data leaks or compliance breaks detected',
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
