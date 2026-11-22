import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateWorkstationStage0Scripts } from './src/stage0/canaryHarness.ts';
import {
  Stage0FailClosedError,
  validateStage0Preconditions,
} from './src/stage0/pathSecurity.ts';
import { computeFourFactorAdapterPriorities } from './src/stage0/priorityModel.ts';
import { runLiveSandboxStage0Verification } from './src/stage0/sandboxVerifier.ts';
import { auditSanitizedStage0Report } from './src/stage0/sanitizer.ts';
import type {
  External86Manifest,
  SanitizedStage0Report,
  Stage0Config,
  VendorEcosystemId,
  WorkflowImportanceTier,
} from './src/stage0/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json({ limit: '2mb' }));

  /**
   * Stage 0 Status Endpoint:
   * Explicitly confirms workstation is UNINSPECTED and Stage 1+ is NOT authorized.
   */
  app.get('/api/stage0/status', (_req, res) => {
    res.json({
      authorizedScope: 'STAGE_0_ONLY',
      stage1Implemented: false,
      workstationInspectionState: 'UNINSPECTED_NO_EVIDENCE_COLLECTED',
      externalSpendCeilingUsd: 0,
      allAdaptersStatus: 'UNVERIFIED',
    });
  });

  /**
   * Validates Stage 0 Config + External 86 Manifest preconditions and generates
   * auditable read-only workstation probe & multi-identity canary scripts.
   */
  app.post('/api/stage0/validate-and-generate', (req, res) => {
    try {
      const { config, manifest } = req.body as {
        config: Stage0Config;
        manifest: External86Manifest;
      };
      const validated = validateStage0Preconditions(config, manifest);
      const scripts = generateWorkstationStage0Scripts(config);
      res.json({
        ok: true,
        normalizedRootCount: validated.normalizedRoots.length,
        normalizedZoneBKey: validated.normalizedZoneBKey,
        scripts,
      });
    } catch (err) {
      if (err instanceof Stage0FailClosedError) {
        res.status(200).json({
          ok: false,
          failClosedCode: err.code,
          detailCode: err.detailCode,
          message: err.message,
        });
        return;
      }
      res.status(200).json({
        ok: false,
        failClosedCode: 'FAIL_CLOSED_CONFIG',
        detailCode: 'UNEXPECTED_VALIDATION_ERROR',
        message: err instanceof Error ? err.message : 'Validation failed',
      });
    }
  });

  /**
   * Executes the live isolated scratch-sandbox syscall verification suite inside /tmp
   * (explicitly separated from the uninspected Dell workstation).
   */
  app.post('/api/stage0/verify-sandbox', (_req, res) => {
    try {
      const summary = runLiveSandboxStage0Verification();
      res.json({ ok: true, summary });
    } catch (err) {
      res.status(500).json({
        ok: false,
        message: err instanceof Error ? err.message : 'Sandbox verification error',
      });
    }
  });

  /**
   * Audits an uploaded or pasted Stage 0 JSON report against the Zero-Leak Sanitizer
   * and computes 4-factor empirical adapter priority scores if valid.
   */
  app.post('/api/stage0/validate-report', (req, res) => {
    const { candidateReport, workflowWeights } = req.body as {
      candidateReport: unknown;
      workflowWeights?: Record<VendorEcosystemId, WorkflowImportanceTier>;
    };

    const audit = auditSanitizedStage0Report(candidateReport);
    if (!audit.valid) {
      res.status(200).json({
        ok: false,
        audit,
      });
      return;
    }

    const report = candidateReport as SanitizedStage0Report;
    const defaultWeights: Record<VendorEcosystemId, WorkflowImportanceTier> = {
      antigravity: 'CRITICAL_ACTIVE_WORK',
      gemini_cli: 'CRITICAL_ACTIVE_WORK',
      codex_cli: 'CRITICAL_ACTIVE_WORK',
      claude_code: 'CRITICAL_ACTIVE_WORK',
      gemini_web: 'HIGH_REFERENCE',
      chatgpt_openai: 'HIGH_REFERENCE',
      claude_web: 'HIGH_REFERENCE',
      manus: 'ARCHIVAL_LOW',
      grok: 'ARCHIVAL_LOW',
      deepseek: 'ARCHIVAL_LOW',
      unknown_structured: 'ARCHIVAL_LOW',
      ...(workflowWeights ?? {}),
    };

    const priorities = computeFourFactorAdapterPriorities(
      report.formatInventory,
      defaultWeights
    );

    res.json({
      ok: true,
      audit,
      report,
      priorities,
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Chronos Ledger Stage 0 Workbench listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
