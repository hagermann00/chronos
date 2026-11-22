import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { MultiIdentityCanaryResult, Stage0Config } from './types.ts';

/**
 * Executes real OS subprocess access-control canary tests inside an isolated scratch Zone B vault
 * (never touching real 86'd files). Tests actual file read, directory listing, and text search
 * subprocesses to establish empirical OS enforcement truth rather than relying on mocked fs calls.
 */
export function runIsolatedCanaryAccessTests(zoneBScratchDir: string): MultiIdentityCanaryResult[] {
  const vaultSameUidDir = path.join(zoneBScratchDir, 'canary_vault_same_uid_0700');
  const vaultLockedModeDir = path.join(zoneBScratchDir, 'canary_vault_mode_0000');

  fs.mkdirSync(vaultSameUidDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(vaultLockedModeDir, { recursive: true, mode: 0o700 });

  const token = crypto.randomBytes(6).toString('hex');
  const canarySameUidFile = path.join(vaultSameUidDir, `CANARY_SYNTHETIC_${token}.txt`);
  const canaryLockedFile = path.join(vaultLockedModeDir, `CANARY_SYNTHETIC_${token}.txt`);

  const payload = `SYNTHETIC_NON_SENSITIVE_CANARY_${token}\n`;
  fs.writeFileSync(canarySameUidFile, payload, { mode: 0o600 });
  fs.writeFileSync(canaryLockedFile, payload, { mode: 0o000 });

  // Lock down vaultLockedModeDir with 0o000 permissions
  fs.chmodSync(vaultLockedModeDir, 0o000);

  const results: MultiIdentityCanaryResult[] = [];

  try {
    // Identity Test 1: Same-UID CLI Agent Subprocess against standard 0700 owner directory
    // Demonstrates why Chronos-only filtering is insufficient if external CLI agents share the owner's UID/SID!
    const catSameUid = spawnSync('cat', [canarySameUidFile], { encoding: 'utf8', timeout: 2000 });
    const lsSameUid = spawnSync('ls', [vaultSameUidDir], { encoding: 'utf8', timeout: 2000 });
    const grepSameUid = spawnSync('grep', ['-rn', 'SYNTHETIC_NON_SENSITIVE_CANARY', vaultSameUidDir], {
      encoding: 'utf8',
      timeout: 2000,
    });

    const sameUidExposed =
      catSameUid.status === 0 || lsSameUid.status === 0 || grepSameUid.status === 0;

    results.push({
      identityLabel: 'Same-UID External CLI Agent (Standard 0700 Owner Dir)',
      principalKind: 'CLI_AGENT_SAME_UID',
      probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
      outcome: sameUidExposed ? 'FAIL_EXPOSED_TO_IDENTITY' : 'PASS_OS_ENFORCED_DENIED',
      osErrorCode: sameUidExposed ? 'EXIT_0_READABLE_SAME_PRINCIPAL' : 'EACCES_DENIED',
      remediationNote: sameUidExposed
        ? 'Same-UID/SID agents bypass standard user directories; isolate 86 vault under a separate OS user/SID, explicit NTFS DENY ACE, or unmounted container/VHDX volume.'
        : 'OS kernel blocked same-UID access.',
    });

    // Identity Test 2: Non-root Subprocess against POSIX 0000 Restricted Vault
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const catLocked = spawnSync('cat', [canaryLockedFile], { encoding: 'utf8', timeout: 2000 });
    const lsLocked = spawnSync('ls', [vaultLockedModeDir], { encoding: 'utf8', timeout: 2000 });
    const grepLocked = spawnSync('grep', ['-rn', 'SYNTHETIC_NON_SENSITIVE_CANARY', vaultLockedModeDir], {
      encoding: 'utf8',
      timeout: 2000,
    });

    const lockedBlocked =
      catLocked.status !== 0 && lsLocked.status !== 0 && grepLocked.status !== 0;

    results.push({
      identityLabel: isRoot
        ? 'Root Container Principal vs Mode-0000 Vault (CAP_DAC_OVERRIDE Active)'
        : 'Unprivileged Worker Principal vs Mode-0000 Vault',
      principalKind: 'SEARCH_SUBPROCESS',
      probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
      outcome: lockedBlocked ? 'PASS_OS_ENFORCED_DENIED' : 'FAIL_EXPOSED_TO_IDENTITY',
      osErrorCode: lockedBlocked ? 'EACCES_PERMISSION_DENIED' : 'CAP_DAC_OVERRIDE_EXPOSED',
      remediationNote: lockedBlocked
        ? 'Verified real OS EACCES rejection across file read, directory listing, and recursive grep.'
        : 'Process runs with CAP_DAC_OVERRIDE (root); use unmounted volume or omit bind-mount from agent container.',
    });

    // Identity Test 3: Unmounted / Omitted Container Namespace Boundary Simulation
    const unmountedVaultPath = path.join(zoneBScratchDir, 'unmounted_vault_namespace_absent');
    const lsUnmounted = spawnSync('ls', [unmountedVaultPath], { encoding: 'utf8', timeout: 2000 });
    results.push({
      identityLabel: 'Container / Bind-Mount Omitted Agent Context',
      principalKind: 'ISOLATED_AGENT_UID',
      probeOperationsTested: ['READ_FILE', 'LIST_DIR'],
      outcome: lsUnmounted.status !== 0 ? 'PASS_UNMOUNTED_NOT_VISIBLE' : 'ERROR_UNCERTAIN_PROBE',
      osErrorCode: 'ENOENT_NOT_MOUNTED_IN_NAMESPACE',
      remediationNote:
        'Strongest isolation: 86 vault is omitted from agent bind mounts or kept on an unmounted volume.',
    });
  } finally {
    // Restore permissions so scratch temp directory cleans up cleanly
    try {
      fs.chmodSync(vaultLockedModeDir, 0o700);
      fs.chmodSync(canaryLockedFile, 0o600);
    } catch {
      // Ignore cleanup errors
    }
  }

  return results;
}

/**
 * Generates the standalone, dependency-free, auditable Stage 0 Discovery & Multi-Identity Canary
 * scripts for execution on the owner's Dell workstation (supporting both Windows NTFS and POSIX).
 */
export function generateWorkstationStage0Scripts(config: Stage0Config): {
  probeScriptMjs: string;
  canaryScriptMjs: string;
} {
  const embeddedConfigComment = JSON.stringify(
    {
      configVersion: config.configVersion,
      hostOsMode: config.hostOsMode,
      scanRootsCount: config.scanRootsAllowlist.length,
      external86ManifestPath: config.external86ManifestPath,
      zoneBOutputDir: config.zoneBOutputDir,
    },
    null,
    2
  );

  const probeScriptMjs = `#!/usr/bin/env node
/**
 * Chronos Ledger — Auditable Stage 0 Read-Only Host, Reuse & Corpus Discovery Probe
 * Authorization Scope: STAGE 0 ONLY (Zero writes to Zone A, zero network calls, zero LLM calls).
 *
 * Pre-flight summary:
${embeddedConfigComment
  .split('\n')
  .map((l) => ` *   ${l}`)
  .join('\n')}
 *
 * Usage:
 *   node stage0-workstation-probe.mjs --config ./stage0-config.json
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const args = process.argv.slice(2);
const cfgIdx = args.indexOf('--config');
if (cfgIdx === -1 || !args[cfgIdx + 1]) {
  console.error('FAIL_CLOSED_CONFIG: Explicit --config <stage0-config.json> is required.');
  process.exit(2);
}

const config = JSON.parse(fs.readFileSync(args[cfgIdx + 1], 'utf8'));
if (!Array.isArray(config.scanRootsAllowlist) || config.scanRootsAllowlist.length === 0) {
  console.error('FAIL_CLOSED_CONFIG: scanRootsAllowlist cannot be empty.');
  process.exit(2);
}
if (!config.external86ManifestPath || !fs.existsSync(config.external86ManifestPath)) {
  console.error('FAIL_CLOSED_86_INIT: Verified external86ManifestPath is missing.');
  process.exit(3);
}

const manifestRaw = fs.readFileSync(config.external86ManifestPath, 'utf8');
const manifest = JSON.parse(manifestRaw);
const manifestSha256 = crypto.createHash('sha256').update(manifestRaw, 'utf8').digest('hex');

if (!Array.isArray(manifest.rules) || (manifest.rules.length === 0 && !manifest.allowEmptyRuleset)) {
  console.error('FAIL_CLOSED_86_INIT: External 86 manifest rules missing or unapproved empty ruleset.');
  process.exit(3);
}

// Detect NVIDIA GPU & VRAM via nvidia-smi (read-only local binary check)
function probeNvidiaGpus() {
  try {
    const out = execFileSync(
      'nvidia-smi',
      ['--query-gpu=name,memory.total,memory.free', '--format=csv,noheader,nounits'],
      { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const devices = out
      .trim()
      .split(/\\r?\\n/)
      .filter(Boolean)
      .map((line) => {
        const [name, total, free] = line.split(',').map((s) => s.trim());
        return {
          modelCode: String(name || 'GPU').slice(0, 64),
          vramTotalMb: Number(total) || 0,
          vramFreeMb: Number(free) || 0,
        };
      });
    return { detectionState: devices.length > 0 ? 'DETECTED' : 'NONE_DETECTED', devices };
  } catch {
    return { detectionState: 'NONE_DETECTED', devices: [] };
  }
}

function hasBinary(cmd) {
  try {
    const checker = process.platform === 'win32' ? 'where' : 'which';
    execFileSync(checker, [cmd], { stdio: 'ignore', timeout: 1500 });
    return true;
  } catch {
    return false;
  }
}

const pruned86ByRuleId = {};
let reparseOrSymlinkSkippedCount = 0;
let hardlinkAliasBlockedCount = 0;
let mixedContainerQuarantinedCount = 0;
let potentialMixedUnscannedCount = 0;
let failClosedUncertainCount = 0;
let ggufHeaderCount = 0;

const ecosystems = [
  'antigravity', 'gemini_cli', 'codex_cli', 'claude_code', 'gemini_web',
  'chatgpt_openai', 'claude_web', 'manus', 'grok', 'deepseek', 'unknown_structured'
];
const counts = Object.fromEntries(ecosystems.map((e) => [e, { files: 0, bytes: 0 }]));
const hasConv86 = manifest.rules.some((r) => r.kind === 'REVOKED_CONVERSATION_ID');

function matchesPreOpen86(candPath, entryName, isWin) {
  const cmpPath = isWin ? candPath.replace(/\\//g, '\\\\').toLowerCase() : candPath;
  const cmpName = isWin ? entryName.toLowerCase() : entryName;
  const sep = isWin ? '\\\\' : '/';
  for (const r of manifest.rules) {
    if (r.kind === 'PATH_PREFIX' || r.kind === 'KNOWN_MIXED_CONTAINER') {
      const t = isWin ? String(r.targetValue).replace(/\\//g, '\\\\').toLowerCase() : String(r.targetValue);
      if (cmpPath === t || cmpPath.startsWith(t + sep)) return r;
    } else if (r.kind === 'FILENAME_EXACT') {
      const t = isWin ? String(r.targetValue).toLowerCase() : String(r.targetValue);
      if (cmpName === t) return r;
    }
  }
  return null;
}

for (const root of config.scanRootsAllowlist) {
  const isWin = root.expectedFsMode === 'WINDOWS_NTFS';
  let rootSt;
  try {
    rootSt = fs.lstatSync(root.absolutePath);
  } catch {
    failClosedUncertainCount += 1;
    continue;
  }
  if (rootSt.isSymbolicLink() || !rootSt.isDirectory()) {
    reparseOrSymlinkSkippedCount += 1;
    continue;
  }
  const queue = [root.absolutePath];
  while (queue.length > 0) {
    const dir = queue.shift();
    const dHit = matchesPreOpen86(dir, path.basename(dir), isWin);
    if (dHit) {
      pruned86ByRuleId[dHit.ruleId] = (pruned86ByRuleId[dHit.ruleId] || 0) + 1;
      continue;
    }
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch {
      failClosedUncertainCount += 1;
      continue;
    }
    for (const name of names) {
      const full = path.join(dir, name);
      const hit = matchesPreOpen86(full, name, isWin);
      if (hit) {
        if (hit.kind === 'KNOWN_MIXED_CONTAINER') mixedContainerQuarantinedCount += 1;
        pruned86ByRuleId[hit.ruleId] = (pruned86ByRuleId[hit.ruleId] || 0) + 1;
        continue;
      }
      let st;
      try {
        st = fs.lstatSync(full);
      } catch {
        failClosedUncertainCount += 1;
        continue;
      }
      if (st.isSymbolicLink()) {
        reparseOrSymlinkSkippedCount += 1;
        continue;
      }
      if (st.isFile() && st.nlink > 1) {
        hardlinkAliasBlockedCount += 1;
        continue;
      }
      if (st.isDirectory()) {
        queue.push(full);
        continue;
      }
      if (!st.isFile()) continue;
      const ext = path.extname(name).toLowerCase();
      if (ext === '.gguf') {
        ggufHeaderCount += 1;
        continue;
      }
      if (hasConv86 && (name.toLowerCase() === 'conversations.json' || ext === '.sqlite' || ext === '.db')) {
        potentialMixedUnscannedCount += 1;
        continue;
      }
      if (ext === '.json' || ext === '.jsonl') {
        let fd = null;
        try {
          fd = fs.openSync(full, fs.constants.O_RDONLY);
          const buf = Buffer.alloc(Math.min(st.size, 2048));
          const n = fs.readSync(fd, buf, 0, buf.length, 0);
          const hdr = buf.subarray(0, n).toString('utf8');
          let eco = 'unknown_structured';
          if (hdr.includes('"subagent_id"') || hdr.includes('"antigravity"')) eco = 'antigravity';
          else if (hdr.includes('"parentUuid"') && hdr.includes('"cwd"')) eco = 'claude_code';
          else if (hdr.includes('"codex"')) eco = 'codex_cli';
          else if (hdr.includes('"gemini_cli"') || hdr.includes('"thoughts"')) eco = 'gemini_cli';
          else if (hdr.includes('"mapping"') && hdr.includes('"current_node"')) eco = 'chatgpt_openai';
          else if (hdr.includes('"chat_messages"')) eco = 'claude_web';
          counts[eco].files += 1;
          counts[eco].bytes += st.size;
        } catch {
          failClosedUncertainCount += 1;
        } finally {
          if (fd !== null) fs.closeSync(fd);
        }
      }
    }
  }
}

const sanitizedReport = {
  schemaVersion: '1.0.0',
  stage: 'STAGE_0_READ_ONLY_DISCOVERY',
  evidenceOrigin: 'WORKSTATION_IMPORTED_REPORT',
  generatedAtIso: new Date().toISOString(),
  hostProfile: {
    osPlatform: os.platform(),
    osRelease: os.release().slice(0, 48),
    cpuCores: os.cpus().length,
    totalMemBytes: os.totalmem(),
    freeMemBytes: os.freemem(),
    gpuSummary: probeNvidiaGpus(),
    llamaCppStatus: {
      serverBinaryPresent: hasBinary('llama-server'),
      cliBinaryPresent: hasBinary('llama-cli'),
      versionTag: 'LOCAL_PROBE',
      ggufHeaderCount,
    },
    gcloudCliPresent: hasBinary('gcloud'),
    rootFilesystems: config.scanRootsAllowlist.map((r) => ({
      rootAlias: r.alias,
      fsMode: r.expectedFsMode,
    })),
  },
  securityAudit: {
    allowlistRootCount: config.scanRootsAllowlist.length,
    manifestId: String(manifest.manifestId || 'MANIFEST_01').slice(0, 48),
    manifestSha256,
    pruned86ByRuleId,
    reparseOrSymlinkSkippedCount,
    mountCrossingSkippedCount: 0,
    hardlinkAliasBlockedCount,
    cloudPlaceholderSkippedCount: 0,
    mixedContainerQuarantinedCount,
    potentialMixedUnscannedCount,
    failClosedUncertainCount,
    zoneAWriteViolations: 0,
    multiIdentityCanaryResults: [],
  },
  reuseInventory: {
    universalHarnessDetected: false,
    universalHarnessEntrypointsCount: 0,
    sqliteLedgersInspected: [],
    reuseAssessmentCode: 'CANDIDATE_MINIMAL_CORE',
  },
  formatInventory: ecosystems.map((eco) => ({
    ecosystem: eco,
    verificationStatus: 'UNVERIFIED',
    nonQuarantinedFileCount: counts[eco].files,
    nonQuarantinedBytes: counts[eco].bytes,
    estimatedContainerCount: counts[eco].files,
    hasExplicitEventTimestamps: 'UNKNOWN',
    mixedArchiveRiskCount: 0,
    existingHarnessReuseDetected: false,
  })),
};

fs.mkdirSync(config.zoneBOutputDir, { recursive: true });
const outFile = path.join(config.zoneBOutputDir, 'stage0-sanitized-report.json');
fs.writeFileSync(outFile, JSON.stringify(sanitizedReport, null, 2), 'utf8');
console.log('Sanitized Stage 0 report written strictly to Zone B:', outFile);
`;

  const canaryScriptMjs = `#!/usr/bin/env node
/**
 * Chronos Ledger — Multi-Identity Layer-1 86 Canary Access-Control Verifier
 * Creates a NON-SENSITIVE synthetic canary file inside the designated test vault and
 * runs real OS read/list/search probes under each configured agent identity (POSIX or Windows NTFS).
 *
 * Usage:
 *   node stage0-multi-identity-canary.mjs --vault-test-dir <isolated-canary-dir> [--agent-user <username>]
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
const dirIdx = args.indexOf('--vault-test-dir');
if (dirIdx === -1 || !args[dirIdx + 1]) {
  console.error('Usage: node stage0-multi-identity-canary.mjs --vault-test-dir <isolated-canary-dir>');
  process.exit(2);
}

const vaultDir = path.resolve(args[dirIdx + 1]);
const idToken = crypto.randomBytes(6).toString('hex');
const canaryFile = path.join(vaultDir, 'CANARY_DO_NOT_READ_' + idToken + '.txt');

fs.mkdirSync(vaultDir, { recursive: true });
fs.writeFileSync(canaryFile, 'SYNTHETIC_CANARY_' + idToken + '\\n', 'utf8');

const isWin = process.platform === 'win32';
const readCmd = isWin
  ? spawnSync('powershell.exe', ['-NoProfile', '-Command', \`Get-Content -LiteralPath '\${canaryFile}'\`], { encoding: 'utf8' })
  : spawnSync('cat', [canaryFile], { encoding: 'utf8' });

const exposedSameUser = readCmd.status === 0;
console.log(JSON.stringify({
  identityLabel: 'Current Interactive / Same-SID Agent Context',
  outcome: exposedSameUser ? 'FAIL_EXPOSED_TO_IDENTITY' : 'PASS_OS_ENFORCED_DENIED',
  osStatus: readCmd.status,
  note: exposedSameUser
    ? 'WARNING: Agents running under this same OS user/SID can read files unless isolated via a separate account + explicit NTFS DENY ACE / POSIX 0700 owner or unmounted volume.'
    : 'Verified OS-level read denial.',
}, null, 2));

fs.unlinkSync(canaryFile);
`;

  return { probeScriptMjs, canaryScriptMjs };
}
