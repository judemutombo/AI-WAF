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
import { analyzeWithLLM } from '../analyzers/llm-analyzer';
import { analyzeOutput } from '../analyzers/output-analyzer';

// ============================================================
// Default policy — can be overridden per-request
// ============================================================
const DEFAULT_POLICY: Required<PolicyConfig> = {
  flagThreshold: 40,
  blockThreshold: 70,
  enabledAnalyzers: ['heuristic', 'llm_intent'],
  customPatterns: [],
  blockedTopics: [],
  maxInputLength: 10000,
};

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
  const policy = { ...DEFAULT_POLICY, ...request.policy };

  // Quick length check
  if (request.input.length > policy.maxInputLength) {
    const decision: WAFDecision = {
      requestId,
      action: 'block',
      overallScore: 100,
      threatLevel: 'critical',
      explanation: `Input exceeds maximum length (${request.input.length} > ${policy.maxInputLength} chars). This may be a context overflow attack.`,
      analyses: [],
      totalLatency: Date.now() - startTime,
      timestamp: new Date().toISOString(),
      originalInput: request.input.substring(0, 500) + '... [truncated]',
    };
    logDecision(decision, request);
    return decision;
  }

  // Run analyzers
  const analyses: AnalysisResult[] = [];

  // 1. HEURISTIC ANALYSIS (always runs — it's fast)
  const heuristicResult = analyzeWithHeuristics(request.input);
  analyses.push(heuristicResult);

  // 2. LLM ANALYSIS (runs if enabled and heuristic score warrants deeper inspection)
  // Optimization: Skip LLM if heuristic says it's clearly safe OR clearly malicious
  if (
    policy.enabledAnalyzers.includes('llm_intent') &&
    heuristicResult.score >= 15 && // Don't waste LLM calls on clearly safe inputs
    heuristicResult.score < 90     // Don't waste time if heuristic is already certain
  ) {
    const llmResult = await analyzeWithLLM(request.input, request.systemPrompt);
    analyses.push(llmResult);
  }

  // 3. COMBINE SCORES
  // Weighted combination: heuristic and LLM each contribute based on confidence
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
    combinedScore >= 20 ? 'low' :
    'none';

  // 5. GENERATE EXPLANATION
  const explanation = generateExplanation(action, analyses, combinedScore);

  const decision: WAFDecision = {
    requestId,
    action,
    overallScore: combinedScore,
    threatLevel,
    explanation,
    analyses,
    totalLatency: Date.now() - startTime,
    timestamp: new Date().toISOString(),
    originalInput: request.input,
  };

  // Log for dashboard
  logDecision(decision, request);

  return decision;
}

/**
 * Analyze an AI output for safety before returning to user
 */
export async function analyzeOutputSafety(
  output: string,
  originalInput: string,
  systemPrompt?: string
): Promise<WAFDecision> {
  const requestId = uuidv4();
  const startTime = Date.now();

  const result = analyzeOutput(output, originalInput, systemPrompt);

  const action =
    result.score >= 70 ? 'block' :
    result.score >= 40 ? 'flag' :
    'allow';

  return {
    requestId,
    action,
    overallScore: result.score,
    threatLevel: result.threatLevel,
    explanation: result.explanation,
    analyses: [result],
    totalLatency: Date.now() - startTime,
    timestamp: new Date().toISOString(),
    originalInput: output,
  };
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Calculate combined score from multiple analyzers.
 * Uses weighted averaging with confidence-based weighting.
 */
function calculateCombinedScore(analyses: AnalysisResult[]): number {
  if (analyses.length === 0) return 0;
  if (analyses.length === 1) return analyses[0].score;

  // Weight by analyzer type
  const weights: Record<string, number> = {
    heuristic: 0.4,   // Pattern matching is reliable but limited
    llm_intent: 0.6,  // LLM analysis is more nuanced
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
    input: request.input.substring(0, 500), // Truncate for storage
    decision,
    agentId: request.agentId,
    sessionId: request.sessionId,
  };

  securityLogs.push(log);

  // Keep log size bounded
  if (securityLogs.length > MAX_LOGS) {
    securityLogs.splice(0, securityLogs.length - MAX_LOGS);
  }
}
