// ============================================================
// AI WAF Server
// Express server exposing the WAF API and security dashboard
// ============================================================

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import { WAFRequest, OutputValidationRequest } from './types';
import {
  analyzeInput,
  analyzeOutputSafety,
  getSecurityLogs,
  getStats,
  clearLogs,
} from './middleware/waf-engine';

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for dashboard inline scripts
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// ============================================================
// API ROUTES
// ============================================================

/**
 * POST /api/waf/analyze
 * Main endpoint — analyze user input before it reaches the AI agent.
 *
 * Request body: {
 *   input: string,          // The user's message
 *   systemPrompt?: string,  // The AI agent's system prompt (for context)
 *   agentId?: string,       // Agent identifier
 *   sessionId?: string,     // Session ID for behavioral tracking
 *   policy?: PolicyConfig   // Custom thresholds
 * }
 *
 * Response: WAFDecision
 */
app.post('/api/waf/analyze', async (req, res) => {
  try {
    const request: WAFRequest = req.body;

    if (!request.input || typeof request.input !== 'string') {
      return res.status(400).json({
        error: 'Missing or invalid "input" field. Provide the user message to analyze.',
      });
    }

    const decision = await analyzeInput(request);

    // Set appropriate HTTP status based on decision
    const statusCode = decision.action === 'block' ? 403 : 200;
    res.status(statusCode).json(decision);

  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Internal WAF error', details: String(error) });
  }
});

/**
 * POST /api/waf/validate-output
 * Validate an AI agent's response before it reaches the user.
 *
 * Request body: {
 *   output: string,         // The AI's response
 *   originalInput: string,  // The user's original message
 *   systemPrompt?: string,  // The agent's system prompt
 * }
 */
app.post('/api/waf/validate-output', async (req, res) => {
  try {
    const request: OutputValidationRequest = req.body;

    if (!request.output || typeof request.output !== 'string') {
      return res.status(400).json({
        error: 'Missing or invalid "output" field.',
      });
    }

    const decision = await analyzeOutputSafety(
      request.output,
      request.originalInput || '',
      request.systemPrompt
    );

    const statusCode = decision.action === 'block' ? 403 : 200;
    res.status(statusCode).json(decision);

  } catch (error) {
    console.error('Output validation error:', error);
    res.status(500).json({ error: 'Internal WAF error', details: String(error) });
  }
});

/**
 * GET /api/waf/logs
 * Retrieve security logs for the dashboard.
 */
app.get('/api/waf/logs', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
  res.json(getSecurityLogs(limit));
});

/**
 * GET /api/waf/stats
 * Retrieve aggregate statistics.
 */
app.get('/api/waf/stats', (req, res) => {
  res.json(getStats());
});

/**
 * POST /api/waf/clear-logs
 * Clear all logs (for demo reset).
 */
app.post('/api/waf/clear-logs', (req, res) => {
  clearLogs();
  res.json({ success: true, message: 'Logs cleared' });
});

/**
 * GET /api/waf/health
 * Health check endpoint.
 */
app.get('/api/waf/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    version: '1.0.0',
    analyzers: ['heuristic', 'llm_intent', 'output_validator'],
  });
});

/**
 * Serve the dashboard for any non-API routes
 */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log(`
╔═════════════════════════════════════════════════════╗
║          🛡️  AI WAF — Active & Ready  🛡️           ║
╠═════════════════════════════════════════════════════╣
║  Server:     http://localhost:${PORT}               ║
║  Dashboard:  http://localhost:${PORT}               ║
║  API:        http://localhost:${PORT}/api/waf       ║
║  Health:     http://localhost:${PORT}/api/waf/health║
╠═════════════════════════════════════════════════════╣
║  Analyzers: Heuristic ✅ | LLM Intent ✅           ║
║  Ouput Validation: (⌐■_■)                           ║
╚═════════════════════════════════════════════════════╝
  `);
});

export default app;
