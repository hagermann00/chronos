import { buildSync } from 'esbuild';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { External86Manifest, Stage0Config } from './types.ts';

export {
  evaluateCanaryIsolationGate,
  runConfiguredIdentityCanaryProbes,
  runIsolatedCanaryAccessTests,
  type MultiIdentityCanaryEvaluation,
  type RunConfiguredIdentityCanaryOptions,
} from './canaryRuntime.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function bundleAuthoritativeNodeCli(entryFilename: string, bannerComment: string): string {
  const entryPoint = path.resolve(__dirname, entryFilename);
  const result = buildSync({
    entryPoints: [entryPoint],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node20',
    write: false,
    minify: false,
    keepNames: true,
    banner: {
      js: `#!/usr/bin/env node\n${bannerComment}`,
    },
  });

  if (!result.outputFiles || result.outputFiles.length === 0) {
    throw new Error(`Failed to bundle authoritative Stage 0 CLI entrypoint: ${entryFilename}`);
  }

  return result.outputFiles[0].text;
}

/**
 * Generates the standalone, zero-dependency, auditable Stage 0 Discovery & Multi-Identity Canary
 * scripts by bundling the EXACT authoritative Stage 0 engine (`pathSecurity.ts`, `traversalEngine.ts`,
 * `sanitizer.ts`, `canaryRuntime.ts`) — eliminating any reduced-security duplicate implementation.
 */
export function generateWorkstationStage0Scripts(
  config: Stage0Config,
  manifest?: External86Manifest
): {
  probeScriptMjs: string;
  canaryScriptMjs: string;
  computedManifestSha256?: string;
} {
  const computedManifestSha256 =
    config.expectedExternal86ManifestSha256 ??
    (manifest
      ? crypto.createHash('sha256').update(JSON.stringify(manifest, null, 2), 'utf8').digest('hex')
      : undefined);

  const embeddedConfigComment = JSON.stringify(
    {
      configVersion: config.configVersion,
      hostOsMode: config.hostOsMode,
      scanRootsCount: config.scanRootsAllowlist.length,
      external86ManifestPath: config.external86ManifestPath,
      expectedManifestSha256Hint: computedManifestSha256 ?? '<REQUIRED_64_HEX_SHA256>',
      configuredCanaryIdentitiesCount: config.canaryAgentIdentities?.length ?? 0,
      zoneBOutputDir: config.zoneBOutputDir,
    },
    null,
    2
  );

  const probeBanner = `/**
 * Chronos Ledger — Authoritative Stage 0 Read-Only Host, Reuse & Corpus Discovery Probe
 * Authorization Scope: STAGE 0 ONLY (Zero writes to Zone A, zero network calls, zero LLM calls).
 * Single-Source Parity: Bundled directly from src/stage0/{pathSecurity,traversalEngine,sanitizer,workstationProbeCli}.ts
 *
 * Pre-flight summary:
${embeddedConfigComment
  .split('\n')
  .map((l) => ` *   ${l}`)
  .join('\n')}
 *
 * Usage:
 *   node stage0-workstation-probe.mjs --config ./stage0-config.json --expected-manifest-sha256 <64-hex-sha256>
 */`;

  const canaryBanner = `/**
 * Chronos Ledger — Authoritative Multi-Identity Layer-1 86 Canary Access-Control Verifier
 * Single-Source Parity: Bundled directly from src/stage0/{canaryRuntime,workstationCanaryCli}.ts
 * Tests READ_FILE, LIST_DIR, and SEARCH_TEXT for EVERY configured agent identity and fails closed
 * (non-zero exit) if any protected identity is exposed or cannot be impersonated.
 *
 * Usage:
 *   node stage0-multi-identity-canary.mjs --vault-test-dir <isolated-canary-dir> [--ram-scratch-dir <ram-dir> --require-ram-partition | --use-ram-scratch] --agent-user <agent-user-1> [--agent-user <agent-user-2>] [--config ./stage0-config.json]
 */`;

  const probeScriptMjs = bundleAuthoritativeNodeCli('workstationProbeCli.ts', probeBanner);
  const canaryScriptMjs = bundleAuthoritativeNodeCli('workstationCanaryCli.ts', canaryBanner);

  return { probeScriptMjs, canaryScriptMjs, computedManifestSha256 };
}
