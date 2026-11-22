import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  CanaryAgentIdentityConfig,
  MultiIdentityCanaryResult,
} from './types.ts';

const SAFE_OS_USERNAME_RE = /^[A-Za-z0-9._\\-]{1,64}$/;

export interface MultiIdentityCanaryEvaluation {
  allProtectedIdentitiesDenied: boolean;
  protectedIdentitiesTested: number;
  protectedIdentitiesDenied: number;
  protectedIdentitiesExposed: number;
  protectedIdentitiesUncertain: number;
  results: MultiIdentityCanaryResult[];
}

function getEffectiveExpectedAccess(
  result: MultiIdentityCanaryResult
): 'MUST_DENY' | 'DIAGNOSTIC_EXPOSURE_CHECK' {
  if (result.expectedAccess) return result.expectedAccess;
  if (
    result.principalKind === 'ISOLATED_AGENT_UID' ||
    result.principalKind === 'SEARCH_SUBPROCESS'
  ) {
    return 'MUST_DENY';
  }
  return 'DIAGNOSTIC_EXPOSURE_CHECK';
}

/**
 * Evaluates multi-identity canary outcomes strictly:
 * Passes ONLY if at least one protected (MUST_DENY) identity was tested AND every single
 * protected identity was empirically denied access (PASS_OS_ENFORCED_DENIED or
 * PASS_UNMOUNTED_NOT_VISIBLE) with zero exposed or uncertain probes.
 */
export function evaluateCanaryIsolationGate(
  results: MultiIdentityCanaryResult[]
): MultiIdentityCanaryEvaluation {
  let protectedIdentitiesTested = 0;
  let protectedIdentitiesDenied = 0;
  let protectedIdentitiesExposed = 0;
  let protectedIdentitiesUncertain = 0;

  for (const res of results) {
    if (getEffectiveExpectedAccess(res) !== 'MUST_DENY') {
      continue;
    }
    protectedIdentitiesTested += 1;
    if (
      res.outcome === 'PASS_OS_ENFORCED_DENIED' ||
      res.outcome === 'PASS_UNMOUNTED_NOT_VISIBLE'
    ) {
      protectedIdentitiesDenied += 1;
    } else if (res.outcome === 'FAIL_EXPOSED_TO_IDENTITY') {
      protectedIdentitiesExposed += 1;
    } else {
      protectedIdentitiesUncertain += 1;
    }
  }

  return {
    allProtectedIdentitiesDenied:
      protectedIdentitiesTested > 0 &&
      protectedIdentitiesDenied === protectedIdentitiesTested &&
      protectedIdentitiesExposed === 0 &&
      protectedIdentitiesUncertain === 0,
    protectedIdentitiesTested,
    protectedIdentitiesDenied,
    protectedIdentitiesExposed,
    protectedIdentitiesUncertain,
    results,
  };
}

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
    // Identity Test 1 (Negative Control): Same-UID CLI Agent Subprocess against standard 0700 owner directory
    // Demonstrates why Chronos-only filtering is insufficient if external CLI agents share the owner's UID/SID.
    const catSameUid = spawnSync('cat', [canarySameUidFile], { encoding: 'utf8', timeout: 2000 });
    const lsSameUid = spawnSync('ls', [vaultSameUidDir], { encoding: 'utf8', timeout: 2000 });
    const grepSameUid = spawnSync('grep', ['-rn', 'SYNTHETIC_NON_SENSITIVE_CANARY', vaultSameUidDir], {
      encoding: 'utf8',
      timeout: 2000,
    });

    const sameUidExposed =
      catSameUid.status === 0 || lsSameUid.status === 0 || grepSameUid.status === 0;

    results.push({
      identityLabel: 'Same-UID External CLI Agent (Unisolated 0700 Control)',
      principalKind: 'CLI_AGENT_SAME_UID',
      expectedAccess: 'DIAGNOSTIC_EXPOSURE_CHECK',
      probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
      outcome: sameUidExposed ? 'FAIL_EXPOSED_TO_IDENTITY' : 'PASS_OS_ENFORCED_DENIED',
      osErrorCode: sameUidExposed ? 'EXIT_0_READABLE_SAME_PRINCIPAL' : 'EACCES_DENIED',
      remediationNote: sameUidExposed
        ? 'Expected control result: Same-UID/SID agents read standard user folders; isolate 86 vault under a separate OS user/SID, explicit NTFS DENY ACE, or unmounted container/VHDX volume.'
        : 'OS kernel blocked same-UID access.',
    });

    // Identity Test 2 (Protected Vault): Non-root Subprocess against POSIX 0000 Restricted Vault
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
      expectedAccess: 'MUST_DENY',
      probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
      outcome: lockedBlocked ? 'PASS_OS_ENFORCED_DENIED' : 'FAIL_EXPOSED_TO_IDENTITY',
      osErrorCode: lockedBlocked ? 'EACCES_PERMISSION_DENIED' : 'CAP_DAC_OVERRIDE_EXPOSED',
      remediationNote: lockedBlocked
        ? 'Verified real OS EACCES rejection across file read, directory listing, and recursive grep.'
        : 'Process runs with CAP_DAC_OVERRIDE (root); use unmounted volume or omit bind-mount from agent container.',
    });

    // Identity Test 3 (Protected Namespace): Unmounted / Omitted Container Namespace Boundary Simulation
    const unmountedVaultPath = path.join(zoneBScratchDir, 'unmounted_vault_namespace_absent');
    const unmountedCanaryFile = path.join(unmountedVaultPath, `CANARY_SYNTHETIC_${token}.txt`);
    const catUnmounted = spawnSync('cat', [unmountedCanaryFile], { encoding: 'utf8', timeout: 2000 });
    const lsUnmounted = spawnSync('ls', [unmountedVaultPath], { encoding: 'utf8', timeout: 2000 });
    const grepUnmounted = spawnSync('grep', ['-rn', 'SYNTHETIC_NON_SENSITIVE_CANARY', unmountedVaultPath], {
      encoding: 'utf8',
      timeout: 2000,
    });
    const unmountedBlocked =
      catUnmounted.status !== 0 && lsUnmounted.status !== 0 && grepUnmounted.status !== 0;
    results.push({
      identityLabel: 'Container / Bind-Mount Omitted Agent Context',
      principalKind: 'ISOLATED_AGENT_UID',
      expectedAccess: 'MUST_DENY',
      probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
      outcome: unmountedBlocked ? 'PASS_UNMOUNTED_NOT_VISIBLE' : 'ERROR_UNCERTAIN_PROBE',
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

type PosixRunnerStrategy =
  | { kind: 'DIRECT' }
  | { kind: 'RUNUSER'; user: string }
  | { kind: 'SUDO_NONINTERACTIVE'; user: string }
  | { kind: 'UNAVAILABLE'; reasonCode: string; detail: string };

function resolvePosixIdentityStrategy(
  targetOsUsername: string | undefined,
  currentOsUsername: string
): PosixRunnerStrategy {
  if (!targetOsUsername || targetOsUsername === currentOsUsername) {
    return { kind: 'DIRECT' };
  }

  if (!SAFE_OS_USERNAME_RE.test(targetOsUsername)) {
    return {
      kind: 'UNAVAILABLE',
      reasonCode: 'INVALID_TARGET_OS_USERNAME',
      detail: 'Configured osUsername failed strict character validation.',
    };
  }

  // First check whether the target user account even exists on this host
  const userLookup = spawnSync('id', ['-u', targetOsUsername], {
    encoding: 'utf8',
    timeout: 2000,
  });
  if (userLookup.status !== 0) {
    return {
      kind: 'UNAVAILABLE',
      reasonCode: 'TARGET_OS_USER_NOT_FOUND',
      detail: 'Configured agent OS user does not exist on this host; refusing to substitute current process identity.',
    };
  }

  // Try runuser -u <user> -- id -un
  const tryRunuser = spawnSync('runuser', ['-u', targetOsUsername, '--', 'id', '-un'], {
    encoding: 'utf8',
    timeout: 2000,
  });
  if (tryRunuser.status === 0 && (tryRunuser.stdout || '').trim() === targetOsUsername) {
    return { kind: 'RUNUSER', user: targetOsUsername };
  }

  // Try sudo -n -u <user> -- id -un (non-interactive only)
  const trySudo = spawnSync('sudo', ['-n', '-u', targetOsUsername, '--', 'id', '-un'], {
    encoding: 'utf8',
    timeout: 2000,
  });
  if (trySudo.status === 0 && (trySudo.stdout || '').trim() === targetOsUsername) {
    return { kind: 'SUDO_NONINTERACTIVE', user: targetOsUsername };
  }

  return {
    kind: 'UNAVAILABLE',
    reasonCode: 'IDENTITY_IMPERSONATION_UNAVAILABLE',
    detail:
      'Current process cannot switch OS identity non-interactively (requires runuser/sudo privilege or executing directly inside the target agent user session). Refusing to fall back to current process identity.',
  };
}

function execProbeCommandPosix(
  strategy: Exclude<PosixRunnerStrategy, { kind: 'UNAVAILABLE' }>,
  cmd: string,
  args: string[]
): { status: number | null; stdout: string; stderr: string } {
  let res;
  if (strategy.kind === 'DIRECT') {
    res = spawnSync(cmd, args, { encoding: 'utf8', timeout: 3000 });
  } else if (strategy.kind === 'RUNUSER') {
    res = spawnSync('runuser', ['-u', strategy.user, '--', cmd, ...args], {
      encoding: 'utf8',
      timeout: 3000,
    });
  } else {
    res = spawnSync('sudo', ['-n', '-u', strategy.user, '--', cmd, ...args], {
      encoding: 'utf8',
      timeout: 3000,
    });
  }
  return {
    status: res.status,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
  };
}

function runWindowsCurrentIdentityProbes(
  vaultDir: string,
  canaryFile: string,
  searchToken: string
): {
  readStatus: number | null;
  listStatus: number | null;
  searchStatus: number | null;
  leakedToken: boolean;
  combinedStderr: string;
} {
  const esc = (s: string) => s.replace(/'/g, "''");
  const readCmd = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', `Get-Content -LiteralPath '${esc(canaryFile)}' -ErrorAction Stop`],
    { encoding: 'utf8', timeout: 4000 }
  );
  const listCmd = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', `Get-ChildItem -LiteralPath '${esc(vaultDir)}' -Force -ErrorAction Stop`],
    { encoding: 'utf8', timeout: 4000 }
  );
  const searchCmd = spawnSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `Select-String -Path '${esc(vaultDir)}\\*' -SimpleMatch '${esc(searchToken)}' -ErrorAction Stop`,
    ],
    { encoding: 'utf8', timeout: 4000 }
  );
  const combinedOut = `${readCmd.stdout ?? ''}\n${listCmd.stdout ?? ''}\n${searchCmd.stdout ?? ''}`;
  const combinedStderr = `${readCmd.stderr ?? ''}\n${listCmd.stderr ?? ''}\n${searchCmd.stderr ?? ''}`;
  return {
    readStatus: readCmd.status,
    listStatus: listCmd.status,
    searchStatus: searchCmd.status,
    leakedToken: combinedOut.includes(searchToken),
    combinedStderr,
  };
}

export interface RunConfiguredIdentityCanaryOptions {
  vaultTestDir: string;
  identities: CanaryAgentIdentityConfig[];
  /**
   * When true, temporarily locks the vaultTestDir to mode 0o000 (POSIX) during probes
   * after planting the synthetic canary file, and restores 0o700 in finally.
   */
  lockVaultMode0000DuringProbe?: boolean;
}

/**
 * Authoritative Multi-Identity Layer-1 Canary Probe Engine used by both the exported
 * standalone workstation canary runner and automated verification tests.
 *
 * Tests READ_FILE, LIST_DIR, and SEARCH_TEXT for EVERY configured agent identity.
 * NEVER silently substitutes the current process identity when a distinct osUsername
 * is requested but cannot be impersonated — fails closed with ERROR_UNCERTAIN_PROBE.
 */
export function runConfiguredIdentityCanaryProbes(
  options: RunConfiguredIdentityCanaryOptions
): MultiIdentityCanaryEvaluation {
  const vaultDir = path.resolve(options.vaultTestDir);
  if (!Array.isArray(options.identities) || options.identities.length === 0) {
    return evaluateCanaryIsolationGate([
      {
        identityLabel: 'Unconfigured Agent Identity List',
        principalKind: 'ISOLATED_AGENT_UID',
        expectedAccess: 'MUST_DENY',
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome: 'ERROR_UNCERTAIN_PROBE',
        osErrorCode: 'NO_AGENT_IDENTITIES_CONFIGURED',
        remediationNote:
          'Configure at least one protected agent identity (--agent-user <user> or canaryAgentIdentities in stage0-config.json).',
      },
    ]);
  }

  const currentOsUser = (() => {
    try {
      return os.userInfo().username;
    } catch {
      return '';
    }
  })();

  const token = crypto.randomBytes(6).toString('hex');
  const searchToken = `SYNTHETIC_CANARY_${token}`;
  const canaryFile = path.join(vaultDir, `CANARY_DO_NOT_READ_${token}.txt`);

  let createdCanaryFile = false;
  let lockedVaultTemporarily = false;
  let vaultExistsAtStart = false;

  try {
    vaultExistsAtStart = fs.existsSync(vaultDir);
    if (vaultExistsAtStart) {
      // Attempt to plant synthetic canary if owner has write access to test vault
      try {
        fs.writeFileSync(canaryFile, `${searchToken}\n`, { mode: 0o600 });
        createdCanaryFile = true;
        if (options.lockVaultMode0000DuringProbe && process.platform !== 'win32') {
          fs.chmodSync(canaryFile, 0o000);
          fs.chmodSync(vaultDir, 0o000);
          lockedVaultTemporarily = true;
        }
      } catch {
        // Vault is already locked/read-only/inaccessible to current user; probe directly without planting
      }
    }

    const results: MultiIdentityCanaryResult[] = [];
    const isWin = process.platform === 'win32';

    for (const identity of options.identities) {
      if (isWin) {
        if (
          identity.osUsername &&
          identity.osUsername.toLowerCase() !== currentOsUser.toLowerCase()
        ) {
          results.push({
            identityLabel: identity.identityLabel,
            principalKind: identity.principalKind,
            expectedAccess: identity.expectedAccess,
            probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
            outcome: 'ERROR_UNCERTAIN_PROBE',
            osErrorCode: 'WIN32_CROSS_PRINCIPAL_REQUIRES_DEDICATED_SESSION',
            remediationNote:
              'On Windows NTFS, execute this canary script directly under each configured agent Windows account (or via a dedicated Scheduled Task / RunAs credential) so the kernel evaluates that SID. Refusing to substitute the current interactive user.',
          });
          continue;
        }

        const winRes = runWindowsCurrentIdentityProbes(vaultDir, canaryFile, searchToken);
        const anySucceeded =
          winRes.readStatus === 0 ||
          winRes.listStatus === 0 ||
          winRes.searchStatus === 0 ||
          winRes.leakedToken;
        const notVisible = !vaultExistsAtStart && !anySucceeded;
        results.push({
          identityLabel: identity.identityLabel,
          principalKind: identity.principalKind,
          expectedAccess: identity.expectedAccess,
          probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
          outcome: anySucceeded
            ? 'FAIL_EXPOSED_TO_IDENTITY'
            : notVisible
              ? 'PASS_UNMOUNTED_NOT_VISIBLE'
              : 'PASS_OS_ENFORCED_DENIED',
          osErrorCode: anySucceeded
            ? 'EXIT_0_EXPOSED_TO_WINDOWS_PRINCIPAL'
            : notVisible
              ? 'ENOENT_VAULT_NOT_VISIBLE'
              : 'WIN32_ACCESS_DENIED',
          remediationNote: anySucceeded
            ? 'Vault is readable/listable/searchable by this Windows principal; enforce explicit NTFS DENY ACE, separate local SID, or unmounted VHDX volume.'
            : 'Verified Windows kernel denial across Get-Content, Get-ChildItem, and Select-String.',
        });
        continue;
      }

      // POSIX execution path
      const strategy = resolvePosixIdentityStrategy(identity.osUsername, currentOsUser);
      if (strategy.kind === 'UNAVAILABLE') {
        results.push({
          identityLabel: identity.identityLabel,
          principalKind: identity.principalKind,
          expectedAccess: identity.expectedAccess,
          probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
          outcome: 'ERROR_UNCERTAIN_PROBE',
          osErrorCode: strategy.reasonCode,
          remediationNote: strategy.detail,
        });
        continue;
      }

      const readRes = execProbeCommandPosix(strategy, 'cat', [canaryFile]);
      const listRes = execProbeCommandPosix(strategy, 'ls', ['-A', vaultDir]);
      const searchRes = execProbeCommandPosix(strategy, 'grep', ['-rn', searchToken, vaultDir]);

      const leakedToken =
        readRes.stdout.includes(searchToken) ||
        listRes.stdout.includes(`CANARY_DO_NOT_READ_${token}`) ||
        searchRes.stdout.includes(searchToken);

      const anySucceeded =
        readRes.status === 0 ||
        listRes.status === 0 ||
        searchRes.status === 0 ||
        leakedToken;

      const combinedStderr = `${readRes.stderr}\n${listRes.stderr}\n${searchRes.stderr}`;
      const isNoSuchFile =
        !vaultExistsAtStart &&
        !anySucceeded &&
        /no such file|cannot access|cannot open/i.test(combinedStderr);
      const isPermDenied =
        !anySucceeded &&
        /permission denied|operation not permitted|eacces|eperm/i.test(combinedStderr);

      let outcome: MultiIdentityCanaryResult['outcome'];
      let osErrorCode: string;
      let remediationNote: string;

      if (anySucceeded) {
        outcome = 'FAIL_EXPOSED_TO_IDENTITY';
        osErrorCode = 'EXIT_0_EXPOSED_TO_IDENTITY';
        remediationNote =
          'Protected test vault was readable, listable, or searchable under this OS identity; isolate under a dedicated UID/SID, strict ACL/0700 ownership, or omit bind-mount.';
      } else if (isNoSuchFile) {
        outcome = 'PASS_UNMOUNTED_NOT_VISIBLE';
        osErrorCode = 'ENOENT_NOT_VISIBLE_TO_IDENTITY';
        remediationNote =
          'Verified vault path is absent/unmounted from this OS identity namespace across read, list, and search probes.';
      } else if (isPermDenied) {
        outcome = 'PASS_OS_ENFORCED_DENIED';
        osErrorCode = 'EACCES_PERMISSION_DENIED';
        remediationNote =
          'Verified OS kernel EACCES denial across file read (cat), directory list (ls), and recursive search (grep).';
      } else {
        outcome = 'ERROR_UNCERTAIN_PROBE';
        osErrorCode = 'UNCERTAIN_NONZERO_EXIT';
        remediationNote =
          'Probe exited non-zero without a clear OS EACCES or ENOENT signal; verify test vault setup and permissions manually.';
      }

      results.push({
        identityLabel: identity.identityLabel,
        principalKind: identity.principalKind,
        expectedAccess: identity.expectedAccess,
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome,
        osErrorCode,
        remediationNote,
      });
    }

    return evaluateCanaryIsolationGate(results);
  } finally {
    if (lockedVaultTemporarily) {
      try {
        fs.chmodSync(vaultDir, 0o700);
        if (createdCanaryFile) {
          fs.chmodSync(canaryFile, 0o600);
        }
      } catch {
        // Ignore cleanup errors
      }
    }
    if (createdCanaryFile) {
      try {
        fs.unlinkSync(canaryFile);
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}
