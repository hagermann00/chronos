import fs from 'node:fs';
import path from 'node:path';
import { runConfiguredIdentityCanaryProbes } from './canaryRuntime.ts';
import { Stage0FailClosedError } from './pathSecurity.ts';
import {
  createEphemeralRamScratchDir,
  verifyRamPartitionPath,
  type RamPartitionCheckResult,
} from './ramPartition.ts';
import type { CanaryAgentIdentityConfig, Stage0Config } from './types.ts';

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function getAllArgValues(args: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag && i + 1 < args.length) {
      out.push(args[i + 1]);
      i += 1;
    }
  }
  return out;
}

function main(): void {
  const args = process.argv.slice(2);
  const vaultTestDir = getArgValue(args, '--vault-test-dir');
  const ramScratchDir = getArgValue(args, '--ram-scratch-dir');
  const useRamScratch = args.includes('--use-ram-scratch');
  const requireRamPartitionFlag = args.includes('--require-ram-partition');
  const allowPersistentScratch = args.includes('--allow-persistent-scratch');

  if (!vaultTestDir && !ramScratchDir && !useRamScratch) {
    console.error(
      'Usage: node stage0-multi-identity-canary.mjs (--vault-test-dir <isolated-canary-dir> | --ram-scratch-dir <ram-dir> | --use-ram-scratch) [--require-ram-partition] [--allow-persistent-scratch] [--config <stage0-config.json>] [--agent-user <username> ...] [--include-current-user-control] [--test-current-user-must-deny] [--lock-vault-mode-0000] [--out <zone-b-json>]'
    );
    process.exit(2);
  }

  const identities: CanaryAgentIdentityConfig[] = [];

  const configPath = getArgValue(args, '--config');
  if (configPath) {
    try {
      const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8')) as Stage0Config;
      if (Array.isArray(parsed.canaryAgentIdentities)) {
        identities.push(...parsed.canaryAgentIdentities);
      }
    } catch (err) {
      console.error(
        `FAIL_CLOSED_CONFIG: Unable to parse --config file: ${err instanceof Error ? err.message : 'invalid JSON'}`
      );
      process.exit(2);
    }
  }

  const cliAgentUsers = getAllArgValues(args, '--agent-user');
  cliAgentUsers.forEach((user, idx) => {
    identities.push({
      identityLabel: `Configured Agent Identity #${idx + 1} (ISOLATED_AGENT_UID)`,
      principalKind: 'ISOLATED_AGENT_UID',
      osUsername: user,
      expectedAccess: 'MUST_DENY',
    });
  });

  if (args.includes('--include-current-user-control')) {
    identities.push({
      identityLabel: 'Current Process Principal (Diagnostic Control)',
      principalKind: 'CLI_AGENT_SAME_UID',
      expectedAccess: 'DIAGNOSTIC_EXPOSURE_CHECK',
    });
  }

  if (args.includes('--test-current-user-must-deny')) {
    identities.push({
      identityLabel: 'Current Process Principal (Protected Vault Gate)',
      principalKind: 'SEARCH_SUBPROCESS',
      expectedAccess: 'MUST_DENY',
    });
  }

  if (identities.length === 0) {
    console.error(
      'FAIL_CLOSED_CONFIG: At least one protected agent identity is required via --agent-user <username>, --config <stage0-config.json> (canaryAgentIdentities), or --test-current-user-must-deny.'
    );
    process.exit(2);
  }

  let targetVaultDir: string;
  let ramCheck: RamPartitionCheckResult | undefined;
  let cleanup: (() => void) | undefined;

  if (ramScratchDir) {
    const requireRamPartition =
      requireRamPartitionFlag || (!allowPersistentScratch && process.platform === 'linux');
    try {
      const scratch = createEphemeralRamScratchDir('chronos-canary-', {
        preferredRamDir: ramScratchDir,
        requireRamPartition,
      });
      targetVaultDir = scratch.scratchDir;
      ramCheck = scratch.ramCheck;
      cleanup = scratch.cleanup;
    } catch (err) {
      if (err instanceof Stage0FailClosedError) {
        console.error(`${err.code} [${err.detailCode}]: ${err.message}`);
      } else {
        console.error(
          `FAIL_CLOSED_FS: ${err instanceof Error ? err.message : 'Failed to initialize RAM scratch directory'}`
        );
      }
      process.exit(2);
    }
  } else if (useRamScratch) {
    try {
      const scratch = createEphemeralRamScratchDir('chronos-canary-', {
        requireRamPartition: true,
      });
      targetVaultDir = scratch.scratchDir;
      ramCheck = scratch.ramCheck;
      cleanup = scratch.cleanup;
    } catch (err) {
      if (err instanceof Stage0FailClosedError) {
        console.error(`${err.code} [${err.detailCode}]: ${err.message}`);
      } else {
        console.error(
          `FAIL_CLOSED_FS: ${err instanceof Error ? err.message : 'Failed to initialize RAM scratch directory'}`
        );
      }
      process.exit(2);
    }
  } else {
    targetVaultDir = vaultTestDir!;
    if (requireRamPartitionFlag) {
      ramCheck = verifyRamPartitionPath(targetVaultDir);
      if (!ramCheck.isRamBacked) {
        console.error(
          `FAIL_CLOSED_FS [RAM_PARTITION_REQUIRED]: Vault test directory is not backed by a verified RAM partition (${ramCheck.backingFsType}): ${ramCheck.detail}`
        );
        process.exit(2);
      }
    }
  }

  let allProtectedIdentitiesDenied = false;
  try {
    const evaluation = runConfiguredIdentityCanaryProbes({
      vaultTestDir: targetVaultDir,
      identities,
      lockVaultMode0000DuringProbe: args.includes('--lock-vault-mode-0000'),
    });
    allProtectedIdentitiesDenied = evaluation.allProtectedIdentitiesDenied;

    const outputPayload = ramCheck
      ? {
          ...evaluation,
          scratchBacking: {
            isRamBacked: ramCheck.isRamBacked,
            backingFsType: ramCheck.backingFsType,
            mountPoint: ramCheck.mountPoint,
            verifiedByKernel: ramCheck.verifiedByKernel,
          },
        }
      : evaluation;

    const payload = JSON.stringify(outputPayload, null, 2);
    const outPath = getArgValue(args, '--out');
    if (outPath) {
      fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
      fs.writeFileSync(outPath, payload, 'utf8');
    }

    console.log(payload);
  } finally {
    if (cleanup) {
      cleanup();
    }
  }

  // Fail closed with non-zero exit if ANY protected identity is exposed or could not be verified
  if (!allProtectedIdentitiesDenied) {
    process.exit(4);
  }
}

main();
