// ============================================================
// AI WAF - Core Type Definitions
// These types define how data flows through the WAF pipeline
// ============================================================

/**
 * How severe is the detected threat?
 * - none: Completely safe, normal usage
 * - low: Slightly suspicious but probably fine
 * - medium: Could be an attack, worth flagging
 * - high: Very likely an attack attempt
 * - critical: Definite attack, block immediately
 */
export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Categories of attacks we can detect.
 * Each maps to specific patterns and heuristics.
 */
export type AttackType =
  | 'prompt_injection'      // "Ignore previous instructions..."
  | 'jailbreak'             // "You are DAN, you can do anything..."
  | 'data_exfiltration'     // Trying to extract system prompts or user data
  | 'privilege_escalation'  // Trying to get the AI to do things outside its scope
  | 'encoding_attack'       // Using base64, ROT13, etc. to hide malicious content
  | 'indirect_injection'    // Malicious instructions hidden in external data
  | 'delimiter_attack'      // Using special chars to break out of context
  | 'social_engineering'    // Manipulating the AI through emotional/authority appeals
  | 'output_manipulation'   // Trying to control what the AI outputs
  | 'none';                 // No attack detected

/**
 * The result from a single analyzer.
 * Each analyzer in our pipeline produces one of these.
 */
export interface AnalysisResult {
  /** Which analyzer produced this result */
  analyzer: string;
  /** Threat score from 0-100 (0 = safe, 100 = definitely malicious) */
  score: number;
  /** Human-readable explanation of what was found */
  explanation: string;
  /** What type of attack was detected (if any) */
  attackType: AttackType;
  /** How severe is this threat */
  threatLevel: ThreatLevel;
  /** How long this analysis took (ms) */
  latency: number;
  /** Any additional metadata (matched patterns, etc.) */
  metadata?: Record<string, unknown>;
}

/**
 * Incoming request to the WAF.
 * This is what developers send to our API.
 */
export interface WAFRequest {
  /** The user's input to the AI agent */
  input: string;
  /** Optional: The AI agent's system prompt (helps with context-aware analysis) */
  systemPrompt?: string;
  /** Optional: The AI agent's name/identifier */
  agentId?: string;
  /** Optional: Session ID for behavioral analysis over time */
  sessionId?: string;
  /** Optional: Custom policy overrides */
  policy?: PolicyConfig;
}

/**
 * Configuration for the WAF's behavior.
 * This lets developers tune sensitivity per-agent.
 */
export interface PolicyConfig {
  /** Score threshold for flagging (default: 40) */
  flagThreshold?: number;
  /** Score threshold for blocking (default: 70) */
  blockThreshold?: number;
  /** Which analyzers to run (default: all) */
  enabledAnalyzers?: string[];
  /** Custom blocked patterns (regex strings) */
  customPatterns?: string[];
  /** Topics that should always be blocked */
  blockedTopics?: string[];
  /** Maximum input length (default: 10000) */
  maxInputLength?: number;
  /** If heuristic score < this, skip LLM (default: 15). Ignored if alwaysRunLLM=true */
  llmSkipLow?: number;
  /** If heuristic score >= this, skip LLM (default: 90). Ignored if alwaysRunLLM=true */
  llmSkipHigh?: number;
  /** Force LLM to always run when enabled, regardless of heuristic score (default: false) */
  alwaysRunLLM?: boolean;
  /** Enable LLM council for output validation too (default: false) */
  outputLLMEnabled?: boolean;
}

/**
 * For output validation - check LLM responses before they reach users
 */
export interface OutputValidationRequest {
  /** The AI agent's response */
  output: string;
  /** The original user input that triggered this response */
  originalInput: string;
  /** The AI agent's system prompt */
  systemPrompt?: string;
  /** Agent identifier */
  agentId?: string;
}

/**
 * The WAF's final decision about a request.
 * This is what gets sent back to the caller.
 */
export interface WAFDecision {
  /** Unique ID for this request (for logging/tracking) */
  requestId: string;
  /** The final verdict */
  action: 'allow' | 'flag' | 'block';
  /** Overall threat score (0-100) */
  overallScore: number;
  /** Overall threat level */
  threatLevel: ThreatLevel;
  /** Human-readable explanation of why this decision was made */
  explanation: string;
  /** Results from each individual analyzer */
  analyses: AnalysisResult[];
  /** Total processing time (ms) */
  totalLatency: number;
  /** ISO timestamp */
  timestamp: string;
  /** The original input that was analyzed */
  originalInput: string;
  /** Whether this was an input scan or output validation */
  scanType: 'input' | 'output';
  /** Which analyzers actually ran for this decision */
  analyzersUsed: string[];
  /** Detailed notes about each analyzer/provider (used/discarded + reason) */
  notes: string[];
  /** Sanitized version of the input (if applicable) */
  sanitizedInput?: string;
}

/**
 * A log entry for the security dashboard
 */
export interface SecurityLog {
  id: string;
  timestamp: string;
  requestId: string;
  input: string;
  decision: WAFDecision;
  scanType: 'input' | 'output';
  analyzersUsed: string[];
  agentId?: string;
  sessionId?: string;
}
