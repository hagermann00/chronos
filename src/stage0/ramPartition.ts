import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Stage0FailClosedError } from './pathSecurity.ts';

export interface RamPartitionCheckResult {
  isRamBacked: boolean;
  backingFsType: string;
  mountPoint: string;
  resolvedPath: string;
  verifiedByKernel: boolean;
  detail: string;
}

const WIN32_DRIVE_RAMDISK = 6;

const WIN32_DRIVE_TYPE_PS_SCRIPT = `
$ErrorActionPreference = 'Stop'
$root = $env:CHRONOS_WIN32_DRIVE_ROOT
if ([string]::IsNullOrEmpty($root)) {
  Write-Output '-1'
  exit 0
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace ChronosStage0 {
  public static class DriveTypeNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetDriveTypeW([MarshalAs(UnmanagedType.LPWStr)] string lpRootPathName);
  }
}
'@
$dt = [ChronosStage0.DriveTypeNative]::GetDriveTypeW($root)
Write-Output $dt
`;

function queryWin32DriveType(driveRoot: string): number {
  if (!driveRoot) {
    return -1;
  }
  try {
    const stdout = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', WIN32_DRIVE_TYPE_PS_SCRIPT],
      {
        encoding: 'utf8',
        timeout: 10_000,
        windowsHide: true,
        env: {
          ...process.env,
          CHRONOS_WIN32_DRIVE_ROOT: driveRoot,
        },
      }
    );
    const parsed = Number.parseInt(stdout.trim(), 10);
    return Number.isFinite(parsed) ? parsed : -1;
  } catch {
    return -1;
  }
}

/**
 * Parses Linux `/proc/self/mountinfo` (or injected `mountInfoText` for testing)
 * to determine the filesystem type and mount point backing `targetRealPath`.
 */
export function detectLinuxMountFsType(
  targetRealPath: string,
  mountInfoText?: string
): { fsType: string; mountPoint: string } | null {
  let content: string;
  try {
    content = mountInfoText ?? fs.readFileSync('/proc/self/mountinfo', 'utf8');
  } catch {
    return null;
  }

  let bestMatch: { fsType: string; mountPoint: string } | null = null;
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    if (!line.trim()) {
      continue;
    }
    const sepIdx = line.indexOf(' - ');
    if (sepIdx === -1) {
      continue;
    }
    const left = line.slice(0, sepIdx);
    const right = line.slice(sepIdx + 3);
    const leftFields = left.trim().split(' ');
    const rightFields = right.trim().split(' ');

    if (leftFields.length < 5 || rightFields.length < 1) {
      continue;
    }

    const mountPoint = leftFields[4]
      .replace(/\\040/g, ' ')
      .replace(/\\011/g, '\t')
      .replace(/\\134/g, '\\');
    const fsType = rightFields[0];

    if (!mountPoint || !fsType) {
      continue;
    }

    const matches =
      targetRealPath === mountPoint ||
      (mountPoint === '/'
        ? targetRealPath.startsWith('/')
        : targetRealPath.startsWith(mountPoint + '/'));

    if (!matches) {
      continue;
    }

    if (bestMatch === null || mountPoint.length >= bestMatch.mountPoint.length) {
      bestMatch = { fsType, mountPoint };
    }
  }

  return bestMatch;
}

/**
 * Verifies whether `candidateDir` is backed by a kernel-verified in-memory RAM filesystem
 * (`tmpfs`/`ramfs` on Linux, `DRIVE_RAMDISK === 6` on Windows). Fails closed on symlinks,
 * non-directories, missing directories, or unsupported platforms.
 */
export function verifyRamPartitionPath(
  candidateDir: string,
  options?: { mountInfoOverride?: string; win32DriveTypeOverride?: number }
): RamPartitionCheckResult {
  const hasMountOverride = options?.mountInfoOverride !== undefined;
  const hasWin32Override = options?.win32DriveTypeOverride !== undefined;

  if (!hasMountOverride && !hasWin32Override) {
    let st: fs.Stats;
    try {
      st = fs.lstatSync(candidateDir);
    } catch (err) {
      return {
        isRamBacked: false,
        backingFsType: 'invalid_target',
        mountPoint: '',
        resolvedPath: candidateDir,
        verifiedByKernel: false,
        detail: `Target path does not exist or cannot be lstat'd: ${(err as Error).message}`,
      };
    }

    if (st.isSymbolicLink() || !st.isDirectory()) {
      return {
        isRamBacked: false,
        backingFsType: 'invalid_target',
        mountPoint: '',
        resolvedPath: candidateDir,
        verifiedByKernel: false,
        detail: st.isSymbolicLink()
          ? 'Target path is a symbolic link; refusing to treat symlink as a verified RAM directory.'
          : 'Target path is not a directory.',
      };
    }
  }

  if (process.platform === 'win32' || hasWin32Override) {
    if (!hasMountOverride) {
      const normalizedCandidate = hasWin32Override
        ? candidateDir.replace(/\//g, '\\')
        : path.win32.resolve(candidateDir);
      const driveMatch = /^([A-Za-z]):(?:\\|$)/.exec(normalizedCandidate);
      const driveRoot = driveMatch ? `${driveMatch[1].toUpperCase()}:\\` : '';

      const driveType = hasWin32Override
        ? (options!.win32DriveTypeOverride as number)
        : queryWin32DriveType(driveRoot);
      const isRam = driveType === WIN32_DRIVE_RAMDISK;

      return {
        isRamBacked: isRam,
        backingFsType: isRam ? 'win32_ramdisk' : `win32_drive_type_${driveType}`,
        mountPoint: driveRoot,
        resolvedPath: candidateDir,
        verifiedByKernel: driveType !== -1,
        detail: isRam
          ? `Verified Win32 RAM disk (DRIVE_RAMDISK=6) at ${driveRoot}.`
          : `Win32 drive ${driveRoot || '<unknown>'} has GetDriveTypeW=${driveType} (expected DRIVE_RAMDISK=6).`,
      };
    }
  }

  if (process.platform === 'linux' || hasMountOverride) {
    let realPath: string;
    try {
      realPath = hasMountOverride
        ? path.posix.resolve(candidateDir)
        : fs.realpathSync(candidateDir);
    } catch (err) {
      return {
        isRamBacked: false,
        backingFsType: 'invalid_target',
        mountPoint: '',
        resolvedPath: candidateDir,
        verifiedByKernel: false,
        detail: `Failed to resolve realpath for candidate directory: ${(err as Error).message}`,
      };
    }

    const mountMatch = detectLinuxMountFsType(realPath, options?.mountInfoOverride);
    if (!mountMatch) {
      return {
        isRamBacked: false,
        backingFsType: 'unknown',
        mountPoint: '',
        resolvedPath: realPath,
        verifiedByKernel: false,
        detail: `Unable to determine kernel mount filesystem type for ${realPath}.`,
      };
    }

    const { fsType, mountPoint } = mountMatch;
    const isRam = fsType === 'tmpfs' || fsType === 'ramfs';

    return {
      isRamBacked: isRam,
      backingFsType: fsType,
      mountPoint,
      resolvedPath: realPath,
      verifiedByKernel: true,
      detail: isRam
        ? `Verified Linux ${fsType} RAM partition mounted at ${mountPoint}.`
        : `Mount point ${mountPoint} is backed by '${fsType}', not an in-memory tmpfs/ramfs partition.`,
    };
  }

  return {
    isRamBacked: false,
    backingFsType: 'unverified_platform',
    mountPoint: '',
    resolvedPath: candidateDir,
    verifiedByKernel: false,
    detail:
      'Automatic kernel RAM-partition detection is unsupported on this OS; failing closed when requireRamPartition=true.',
  };
}

/**
 * Resolves a base scratch directory, enforcing RAM-backed storage when `requireRamPartition`
 * is enabled (default `true` on Linux).
 */
export function resolveRamScratchBaseDir(options?: {
  preferredRamDir?: string;
  requireRamPartition?: boolean;
  mountInfoOverride?: string;
}): { baseDir: string; ramCheck: RamPartitionCheckResult } {
  const requireRam = options?.requireRamPartition ?? process.platform === 'linux';
  const explicit = options?.preferredRamDir ?? process.env.CHRONOS_RAM_SCRATCH_DIR;

  if (explicit) {
    const ramCheck = verifyRamPartitionPath(explicit, {
      mountInfoOverride: options?.mountInfoOverride,
    });
    if (requireRam && !ramCheck.isRamBacked) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_FS',
        'RAM_PARTITION_REQUIRED',
        `Explicit scratch directory is not backed by a verified RAM partition (${ramCheck.backingFsType}): ${ramCheck.detail}`
      );
    }
    return {
      baseDir: ramCheck.resolvedPath || explicit,
      ramCheck,
    };
  }

  if (process.platform === 'linux' && fs.existsSync('/dev/shm')) {
    const ramCheck = verifyRamPartitionPath('/dev/shm', {
      mountInfoOverride: options?.mountInfoOverride,
    });
    if (ramCheck.isRamBacked) {
      return {
        baseDir: ramCheck.resolvedPath,
        ramCheck,
      };
    }
  }

  if (requireRam) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_FS',
      'RAM_PARTITION_UNAVAILABLE',
      'No verified in-memory RAM partition (tmpfs/ramfs or Windows RAM disk) is available; refusing to write scratch files to persistent disk.'
    );
  }

  const tmpBase = os.tmpdir();
  const ramCheck = verifyRamPartitionPath(tmpBase, {
    mountInfoOverride: options?.mountInfoOverride,
  });
  return {
    baseDir: ramCheck.resolvedPath || tmpBase,
    ramCheck,
  };
}

function bestEffortUnlockTree(rootDir: string): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(rootDir);
  } catch {
    return;
  }

  if (st.isSymbolicLink() || !st.isDirectory()) {
    return;
  }

  try {
    fs.chmodSync(rootDir, 0o700);
  } catch {
    // Best-effort unlock only
  }

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(rootDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      bestEffortUnlockTree(fullPath);
    } else {
      try {
        fs.chmodSync(fullPath, 0o600);
      } catch {
        // Best-effort unlock only
      }
    }
  }
}

/**
 * Creates a mode-0700 ephemeral scratch directory on a verified RAM partition
 * (or fallback temp dir when `requireRamPartition=false`) and provides an idempotent `cleanup()`.
 */
export function createEphemeralRamScratchDir(
  prefix: string,
  options?: { preferredRamDir?: string; requireRamPartition?: boolean }
): { scratchDir: string; ramCheck: RamPartitionCheckResult; cleanup: () => void } {
  const { baseDir, ramCheck } = resolveRamScratchBaseDir(options);
  const scratchDir = fs.mkdtempSync(path.join(baseDir, prefix));

  try {
    fs.chmodSync(scratchDir, 0o700);
  } catch (err) {
    if (process.platform !== 'win32') {
      throw err;
    }
  }

  const cleanup = (): void => {
    if (!fs.existsSync(scratchDir)) {
      return;
    }
    bestEffortUnlockTree(scratchDir);
    fs.rmSync(scratchDir, { recursive: true, force: true });
  };

  return {
    scratchDir,
    ramCheck,
    cleanup,
  };
}
