// ============================================================
// WAF Engine — The Orchestrator
// Runs all analyzers, combines results, makes the final call.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import {
  WAFRequest,
  WAFDecision,
  AnalysisResult,
  PolicyConfig,
  ThreatLevel,
  SecurityLog,
} from '../types';
import { analyzeWithHeuristics } from '../analyzers/heuristic';
import { analyzeWithLLMCouncil } from '../analyzers/llm-analyzer';
import { analyzeOutput } from '../analyzers/output-analyzer';

// ============================================================
// Default policy — the baseline config
// ============================================================
const DEFAULT_POLICY: Required<PolicyConfig> = {
  flagThreshold: 40,
  blockThreshold: 70,
  enabledAnalyzers: ['heuristic', 'llm_intent'],
  customPatterns: [],
  blockedTopics: [],
  maxInputLength: 10000,
  llmSkipLow: 15,
  llmSkipHigh: 90,
  alwaysRunLLM: false,
  outputLLMEnabled: false,
};

// ============================================================
// Global runtime config — starts as a copy of defaults.
// The dashboard can modify this at runtime via the API.
// Per-request overrides still take priority over this.
// ============================================================
let globalPolicy: Required<PolicyConfig> = { ...DEFAULT_POLICY };

/**
 * Get the current active policy (for the dashboard to display)
 */
export function getGlobalPolicy(): Required<PolicyConfig> {
  return { ...globalPolicy };
}

/**
 * Update the global policy from the dashboard.
 * Only provided fields are updated — everything else stays.
 */
export function updateGlobalPolicy(patch: Partial<PolicyConfig>): Required<PolicyConfig> {
  globalPolicy = {
    ...globalPolicy,
    ...patch,
    // Ensure arrays are replaced, not merged
    enabledAnalyzers: patch.enabledAnalyzers ?? globalPolicy.enabledAnalyzers,
    customPatterns: patch.customPatterns ?? globalPolicy.customPatterns,
    blockedTopics: patch.blockedTopics ?? globalPolicy.blockedTopics,
  };
  return { ...globalPolicy };
}

/**
 * Reset global policy back to defaults
 */
export function resetGlobalPolicy(): Required<PolicyConfig> {
  globalPolicy = { ...DEFAULT_POLICY };
  return { ...globalPolicy };
}

// ============================================================
// In-memory security log (in production, use a database)
// ============================================================
const securityLogs: SecurityLog[] = [];
const MAX_LOGS = 1000;

/**
 * Get recent security logs for the dashboard
 */
export function getSecurityLogs(limit = 50): SecurityLog[] {
  return securityLogs.slice(-limit).reverse();
}

/**
 * Get aggregate stats for the dashboard
 */
export function getStats() {
  const total = securityLogs.length;
  const blocked = securityLogs.filter(l => l.decision.action === 'block').length;
  const flagged = securityLogs.filter(l => l.decision.action === 'flag').length;
  const allowed = securityLogs.filter(l => l.decision.action === 'allow').length;

  // Attack type distribution
  const attackTypes: Record<string, number> = {};
  for (const log of securityLogs) {
    for (const analysis of log.decision.analyses) {
      if (analysis.attackType !== 'none') {
        attackTypes[analysis.attackType] = (attackTypes[analysis.attackType] || 0) + 1;
      }
    }
  }

  // Average latency
  const avgLatency = total > 0
    ? Math.round(securityLogs.reduce((sum, l) => sum + l.decision.totalLatency, 0) / total)
    : 0;

  return {
    total,
    blocked,
    flagged,
    allowed,
    blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0,
    attackTypes,
    avgLatency,
  };
}

/**
 * Clear logs (for dashboard reset)
 */
export function clearLogs() {
  securityLogs.length = 0;
}

// ============================================================
// CORE ANALYSIS PIPELINE
// ============================================================

/**
 * Analyze an input through all enabled analyzers.
 * Heuristics run first (fast), LLM runs in parallel if enabled.
 */
export async function analyzeInput(request: WAFRequest): Promise<WAFDecision> {
  const requestId = uuidv4();
  const startTime = Date.now();
  const policy = { ...globalPolicy, ...request.policy };

  const analyzersUsed: string[] = [];
  const notes: string[] = [];

  // Quick length check
  if (request.input.length > policy.maxInputLength) {
    const decision: WAFDecision = {
      requestId, action: 'block', overallScore: 100, threatLevel: 'critical',
      explanation: `Input exceeds maximum length (${request.input.length} > ${policy.maxInputLength} chars). This may be a context overflow attack.`,
      analyses: [], totalLatency: Date.now() - startTime,
      timestamp: new Date().toISOString(),
      originalInput: request.input.substring(0, 500) + '... [truncated]',
      scanType: 'input', analyzersUsed: ['length_check'],
      notes: ['Input auto-blocked: length exceeded'],
    };
    logDecision(decision, request);
    return decision;
  }

  const analyses: AnalysisResult[] = [];

  // 0. CUSTOM PATTERNS
  if (policy.customPatterns.length > 0) {
    const customResult = checkCustomPatterns(request.input, policy.customPatterns);
    if (customResult.score > 0) {
      analyses.push(customResult);
      analyzersUsed.push('custom_patterns');
      notes.push('custom patterns used');
    }
  }

  // 0b. BLOCKED TOPICS
  if (policy.blockedTopics.length > 0) {
    const topicResult = checkBlockedTopics(request.input, policy.blockedTopics);
    if (topicResult.score > 0) {
      analyses.push(topicResult);
      analyzersUsed.push('blocked_topics');
      notes.push('blocked topics matched');
    }
  }

  // 1. HEURISTIC ANALYSIS
  if (policy.enabledAnalyzers.includes('heuristic')) {
    const heuristicResult = analyzeWithHeuristics(request.input);
    analyses.push(heuristicResult);
    analyzersUsed.push('heuristic');
    notes.push(`heuristic used (score: ${heuristicResult.score})`);
  }

  // 2. LLM COUNCIL ANALYSIS
  if (policy.enabledAnalyzers.includes('llm_intent')) {
    const topHeuristicScore = Math.max(0, ...analyses.map(a => a.score));
    const shouldRunLLM = policy.alwaysRunLLM || (
      topHeuristicScore >= policy.llmSkipLow &&
      topHeuristicScore < policy.llmSkipHigh
    );

    if (shouldRunLLM) {
      const council = await analyzeWithLLMCouncil(
        request.input,
        request.systemPrompt,
        policy.blockThreshold,
        policy.flagThreshold
      );

      // Check if the entire council failed (all providers errored out)
      const councilTotallyFailed = council.activeProviders.length === 0 && council.discardedProviders.length > 0;

      if (councilTotallyFailed) {
        // Council failed — mark it
        analyzersUsed.push('llm_council(failed)');
        notes.push(...council.providerNotes);
        notes.push('⚠ LLM council FAILED: all providers unavailable');

        for (const p of council.discardedProviders) {
          analyzersUsed.push(`llm:${p}(failed)`);
        }

        // FALLBACK: force heuristic as last resort if it wasn't already run
        if (!policy.enabledAnalyzers.includes('heuristic')) {
          const fallbackResult = analyzeWithHeuristics(request.input);
          analyses.push(fallbackResult);
          analyzersUsed.push('heuristic(fallback)');
          notes.push(`heuristic used as FALLBACK (score: ${fallbackResult.score}) — forced because all LLM providers failed`);
        }
      } else {
        // Council succeeded (at least one provider worked)
        analyses.push(council.result);
        analyzersUsed.push('llm_council');
        notes.push(...council.providerNotes);

        for (const p of council.activeProviders) {
          analyzersUsed.push(`llm:${p}`);
        }
        for (const p of council.discardedProviders) {
          analyzersUsed.push(`llm:${p}(failed)`);
        }
      }
    } else {
      analyzersUsed.push('llm_council(skipped)');
      notes.push(`LLM council skipped (heuristic score ${topHeuristicScore} outside range ${policy.llmSkipLow}-${policy.llmSkipHigh})`);
    }
  }
  
  // 3. COMBINE SCORES
  const combinedScore = calculateCombinedScore(analyses);

  // 4. MAKE DECISION
  const action =
    combinedScore >= policy.blockThreshold ? 'block' :
    combinedScore >= policy.flagThreshold ? 'flag' :
    'allow';

  const threatLevel: ThreatLevel =
    combinedScore >= 80 ? 'critical' :
    combinedScore >= 60 ? 'high' :
    combinedScore >= 40 ? 'medium' :
    combinedScore >= 20 ? 'low' : 'none';

  const explanation = generateExplanation(action, analyses, combinedScore);

  const decision: WAFDecision = {
    requestId, action, overallScore: combinedScore, threatLevel, explanation,
    analyses, totalLatency: Date.now() - startTime,
    timestamp: new Date().toISOString(),
    originalInput: request.input, scanType: 'input',
    analyzersUsed, notes,
  };

  logDecision(decision, request);
  return decision;
}

/**
 * Analyze an AI output for safety before returning to user
 */
export async function analyzeOutputSafety(
  output: string,
  originalInput: string,
  systemPrompt?: string,
  agentId?: string
): Promise<WAFDecision> {
  const requestId = uuidv4();
  const startTime = Date.now();
  const policy = { ...globalPolicy };

  const analyses: AnalysisResult[] = [];
  const analyzersUsed: string[] = ['output_validator'];
  const notes: string[] = ['output validator used'];

  // 1. Standard output analysis (heuristic-based)
  const result = analyzeOutput(output, originalInput, systemPrompt);
  analyses.push(result);

  // 2. LLM council for output (if enabled)
  if (policy.outputLLMEnabled && policy.enabledAnalyzers.includes('llm_intent')) {
    const council = await analyzeWithLLMCouncil(
      `[OUTPUT VALIDATION] The following is an AI agent's response to validate for safety:\n\n${output}`,
      systemPrompt,
      policy.blockThreshold,
      policy.flagThreshold
    );

    const councilTotallyFailed = council.activeProviders.length === 0 && council.discardedProviders.length > 0;

    if (councilTotallyFailed) {
      analyzersUsed.push('llm_council(failed)');
      notes.push(...council.providerNotes);
      notes.push('⚠ LLM council FAILED for output: all providers unavailable — relying on output validator only');
      for (const p of council.discardedProviders) analyzersUsed.push(`llm:${p}(failed)`);
    } else {
      analyses.push(council.result);
      analyzersUsed.push('llm_council');
      notes.push(...council.providerNotes);
      for (const p of council.activeProviders) analyzersUsed.push(`llm:${p}`);
      for (const p of council.discardedProviders) analyzersUsed.push(`llm:${p}(failed)`);
    }
  }

  // Combine scores
  const combinedScore = analyses.length > 1
    ? calculateCombinedScore(analyses)
    : result.score;

  const action =
    combinedScore >= policy.blockThreshold ? 'block' :
    combinedScore >= policy.flagThreshold ? 'flag' :
    'allow';

  const threatLevel: ThreatLevel =
    combinedScore >= 80 ? 'critical' : combinedScore >= 60 ? 'high' :
    combinedScore >= 40 ? 'medium' : combinedScore >= 20 ? 'low' : 'none';

  const decision: WAFDecision = {
    requestId, action, overallScore: combinedScore,
    threatLevel, explanation: result.explanation,
    analyses, totalLatency: Date.now() - startTime,
    timestamp: new Date().toISOString(),
    originalInput: output, scanType: 'output',
    analyzersUsed, notes,
  };

  const log: SecurityLog = {
    id: decision.requestId, timestamp: decision.timestamp,
    requestId: decision.requestId, input: output.substring(0, 500),
    decision, scanType: 'output', analyzersUsed, agentId,
  };
  securityLogs.push(log);
  if (securityLogs.length > MAX_LOGS) securityLogs.splice(0, securityLogs.length - MAX_LOGS);

  return decision;
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Check input against user-defined custom regex patterns from the dashboard.
 * These are additional patterns the security team adds for their specific use case.
 */
function checkCustomPatterns(input: string, patterns: string[]): AnalysisResult {
  const startTime = Date.now();
  const matched: string[] = [];

  for (const patternStr of patterns) {
    try {
      const regex = new RegExp(patternStr, 'i');
      if (regex.test(input)) {
        matched.push(patternStr);
      }
    } catch {
      // Skip invalid regex silently
    }
  }

  const score = matched.length > 0 ? Math.min(100, 50 + matched.length * 15) : 0;

  return {
    analyzer: 'custom_patterns',
    score,
    explanation: matched.length > 0
      ? `Matched ${matched.length} custom pattern(s): ${matched.map(p => `/${p}/`).join(', ')}`
      : 'No custom patterns matched',
    attackType: matched.length > 0 ? 'prompt_injection' : 'none',
    threatLevel: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'none',
    latency: Date.now() - startTime,
    metadata: { matchedPatterns: matched },
  };
}

/**
 * Check if input mentions any blocked topics configured in the dashboard.
 * Simple case-insensitive substring matching.
 */
function checkBlockedTopics(input: string, topics: string[]): AnalysisResult {
  const startTime = Date.now();
  const lowerInput = input.toLowerCase();
  const matched = topics.filter(topic => lowerInput.includes(topic.toLowerCase()));

  const score = matched.length > 0 ? Math.min(100, 60 + matched.length * 10) : 0;

  return {
    analyzer: 'blocked_topics',
    score,
    explanation: matched.length > 0
      ? `Input contains blocked topic(s): ${matched.join(', ')}`
      : 'No blocked topics found',
    attackType: matched.length > 0 ? 'prompt_injection' : 'none',
    threatLevel: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'none',
    latency: Date.now() - startTime,
    metadata: { matchedTopics: matched },
  };
}

/**
 * Calculate combined score from multiple analyzers.
 * Uses weighted averaging with confidence-based weighting.
 */
function calculateCombinedScore(analyses: AnalysisResult[]): number {
  if (analyses.length === 0) return 0;
  if (analyses.length === 1) return analyses[0].score;

  // Weight by analyzer type
  const weights: Record<string, number> = {
    heuristic: 0.4,
    llm_intent: 0.6,
    llm_council: 0.6,     // Council has same weight as single LLM
    custom_patterns: 0.5,
    blocked_topics: 0.7,
    output_validator: 0.5,
  };

  let weightedSum = 0;
  let totalWeight = 0;

  for (const analysis of analyses) {
    const weight = weights[analysis.analyzer] || 0.5;

    // If LLM has low confidence, reduce its weight
    const confidence = (analysis.metadata?.confidence as number) || 80;
    const adjustedWeight = weight * (confidence / 100);

    weightedSum += analysis.score * adjustedWeight;
    totalWeight += adjustedWeight;
  }

  // Also factor in: if ANY analyzer flagged critical, don't let averaging hide it
  const maxScore = Math.max(...analyses.map(a => a.score));
  const avgScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

  // Final score: blend of weighted average and max (so critical signals aren't diluted)
  return Math.round(avgScore * 0.6 + maxScore * 0.4);
}

/**
 * Generate a human-readable explanation of the WAF decision.
 * This is what security teams see in the dashboard.
 */
function generateExplanation(
  action: 'allow' | 'flag' | 'block',
  analyses: AnalysisResult[],
  score: number
): string {
  if (action === 'allow') {
    return `Input appears safe (score: ${score}/100). No significant threats detected.`;
  }

  // Collect all non-trivial findings
  const findings = analyses
    .filter(a => a.score > 20)
    .sort((a, b) => b.score - a.score);

  if (findings.length === 0) {
    return `Input ${action === 'block' ? 'blocked' : 'flagged'} (score: ${score}/100).`;
  }

  const primary = findings[0];
  let explanation = `${action === 'block' ? '🚫 BLOCKED' : '⚠️ FLAGGED'} (score: ${score}/100) — `;
  explanation += `Primary threat: ${formatAttackType(primary.attackType)}. `;
  explanation += primary.explanation;

  if (findings.length > 1) {
    const secondary = findings.slice(1).map(f => formatAttackType(f.attackType));
    explanation += ` Additional signals: ${secondary.join(', ')}.`;
  }

  return explanation;
}

/**
 * Format attack type for human display
 */
function formatAttackType(type: string): string {
  return type
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Log a decision for the security dashboard
 */
function logDecision(decision: WAFDecision, request: WAFRequest) {
  const log: SecurityLog = {
    id: decision.requestId,
    timestamp: decision.timestamp,
    requestId: decision.requestId,
    input: request.input.substring(0, 500),
    decision,
    scanType: decision.scanType,
    analyzersUsed: decision.analyzersUsed,
    agentId: request.agentId,
    sessionId: request.sessionId,
  };

  securityLogs.push(log);
  if (securityLogs.length > MAX_LOGS) {
    securityLogs.splice(0, securityLogs.length - MAX_LOGS);
  }
}
