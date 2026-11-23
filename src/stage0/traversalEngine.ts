import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  evaluatePreOpen86Rules,
  matchArchiveEntryAgainst86,
  Stage0FailClosedError,
  validateStage0Preconditions,
  verifyManifestSha256,
} from './pathSecurity.ts';
import { assertSanitizedStage0Report } from './sanitizer.ts';
import { checkSqliteSafeForImmutableInspection } from './sqliteGuard.ts';
import type {
  External86Manifest,
  FormatInventoryRecord,
  MultiIdentityCanaryResult,
  OsPlatformMode,
  Rule86Entry,
  SanitizedStage0Report,
  SqliteTableSchemaSummary,
  Stage0Config,
  VendorEcosystemId,
} from './types.ts';
import {
  buildSqliteReadOnlyImmutableUri,
  inspectWin32NtfsHandleNoFollow,
  verifyWin32NtfsEntryNoFollow,
  type Win32SafeCheckResult,
} from './win32NtfsGuard.ts';

export interface TraversalTelemetry {
  readdirCalls: number;
  lstatCalls: number;
  openCalls: number;
  openedPaths: string[];
}

const ALL_ECOSYSTEMS: VendorEcosystemId[] = [
  'antigravity',
  'gemini_cli',
  'codex_cli',
  'claude_code',
  'gemini_web',
  'chatgpt_openai',
  'claude_web',
  'manus',
  'grok',
  'deepseek',
  'unknown_structured',
];

const UNSCANNABLE_ARCHIVE_EXTS = new Set([
  '.tar',
  '.tgz',
  '.gz',
  '.7z',
  '.rar',
  '.bz2',
  '.xz',
]);

export type SafeOpenFailureReason =
  | 'SYMLINK_RACE'
  | 'HARDLINK_RACE'
  | 'CLOUD_PLACEHOLDER'
  | 'WIN32_NATIVE_VERIFICATION_UNAVAILABLE'
  | 'REVOKED_INODE_RACE'
  | 'PATH_OR_RULE_RACE'
  | 'STAT_IDENTITY_MISMATCH'
  | 'OPEN_OR_FSTAT_ERROR';

export type SafeOpenResult =
  | { ok: true; fd: number; fstat: fs.Stats }
  | { ok: false; reason: SafeOpenFailureReason; matchedRuleId?: string };

function mapWin32FailureToSafeOpenResult(
  res: Extract<Win32SafeCheckResult, { ok: false }>
): SafeOpenResult {
  switch (res.reason) {
    case 'CLOUD_PLACEHOLDER':
      return { ok: false, reason: 'CLOUD_PLACEHOLDER' };
    case 'REPARSE_OR_SYMLINK':
      return { ok: false, reason: 'SYMLINK_RACE' };
    case 'HARDLINK':
      return { ok: false, reason: 'HARDLINK_RACE' };
    case 'REVOKED_NTFS_FILE_ID':
      return {
        ok: false,
        reason: 'REVOKED_INODE_RACE',
        matchedRuleId: res.matchedRuleId,
      };
    case 'PATH_ESCAPE_OR_86':
      return {
        ok: false,
        reason: 'PATH_OR_RULE_RACE',
        matchedRuleId: res.matchedRuleId,
      };
    case 'WIN32_NATIVE_VERIFICATION_UNAVAILABLE':
      return { ok: false, reason: 'WIN32_NATIVE_VERIFICATION_UNAVAILABLE' };
  }
}

/**
 * Atomically opens a regular file with O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
 * and verifies post-open fstat() + Linux /proc/self/fd containment invariants against the
 * pre-open lstat() snapshot (and Win32 NTFS handle attributes on Windows) to eliminate
 * check-to-open (TOCTOU) symlink, hardlink, FIFO, and mount/rename races before any payload bytes are read.
 */
export function openRegularFileNoFollowVerified(params: {
  fullPath: string;
  entryName: string;
  expectedStat: fs.Stats;
  rootRealPath: string;
  rootCanonicalKey?: string;
  mode: OsPlatformMode;
  ntfsCaseSensitiveDir?: boolean;
  revokedPosixDevInos: Set<string>;
  rules: Rule86Entry[];
}): SafeOpenResult {
  let preWin: Win32SafeCheckResult | null = null;
  if (process.platform === 'win32') {
    preWin = verifyWin32NtfsEntryNoFollow({
      targetPath: params.fullPath,
      rootCanonicalKey: params.rootCanonicalKey ?? params.rootRealPath,
      ntfsCaseSensitiveDir: params.ntfsCaseSensitiveDir,
      rules: params.rules,
    });
    if (!preWin.ok) {
      return mapWin32FailureToSafeOpenResult(preWin);
    }
  }

  const fsConsts = fs.constants as Record<string, number>;
  const openFlags =
    fs.constants.O_RDONLY |
    (fs.constants.O_NOFOLLOW ?? 0) |
    (fs.constants.O_NONBLOCK ?? 0) |
    (fsConsts.O_CLOEXEC ?? 0);

  let fd: number;
  try {
    fd = fs.openSync(params.fullPath, openFlags);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ELOOP') {
      return { ok: false, reason: 'SYMLINK_RACE' };
    }
    return { ok: false, reason: 'OPEN_OR_FSTAT_ERROR' };
  }

  try {
    const fst = fs.fstatSync(fd);

    if (!fst.isFile()) {
      fs.closeSync(fd);
      return { ok: false, reason: 'STAT_IDENTITY_MISMATCH' };
    }

    if (fst.dev !== params.expectedStat.dev || fst.ino !== params.expectedStat.ino) {
      fs.closeSync(fd);
      return { ok: false, reason: 'STAT_IDENTITY_MISMATCH' };
    }

    if (process.platform === 'win32') {
      const postWin = verifyWin32NtfsEntryNoFollow({
        targetPath: params.fullPath,
        rootCanonicalKey: params.rootCanonicalKey ?? params.rootRealPath,
        ntfsCaseSensitiveDir: params.ntfsCaseSensitiveDir,
        rules: params.rules,
      });
      if (!postWin.ok) {
        fs.closeSync(fd);
        return mapWin32FailureToSafeOpenResult(postWin);
      }
      if (!preWin || !preWin.ok || postWin.meta.ntfsFileId128 !== preWin.meta.ntfsFileId128) {
        fs.closeSync(fd);
        return { ok: false, reason: 'STAT_IDENTITY_MISMATCH' };
      }
    }

    const postDevIno = `${fst.dev}:${fst.ino}`;
    if (params.revokedPosixDevInos.has(postDevIno)) {
      fs.closeSync(fd);
      const hit = evaluatePreOpen86Rules({
        candidatePath: params.fullPath,
        entryName: params.entryName,
        mode: params.mode,
        ntfsCaseSensitiveDir: params.ntfsCaseSensitiveDir,
        posixDevIno: postDevIno,
        rules: params.rules,
      });
      return {
        ok: false,
        reason: 'REVOKED_INODE_RACE',
        matchedRuleId: hit.ruleId ?? 'R86_INODE_HIT',
      };
    }

    if (fst.nlink > 1) {
      fs.closeSync(fd);
      return { ok: false, reason: 'HARDLINK_RACE' };
    }

    if ((fst.mode & 0o444) === 0) {
      fs.closeSync(fd);
      return { ok: false, reason: 'OPEN_OR_FSTAT_ERROR' };
    }

    // On Linux, verify kernel-resolved descriptor path to defeat intermediate directory symlink swaps
    if (process.platform === 'linux') {
      try {
        const fdRealPath = fs.readlinkSync(`/proc/self/fd/${fd}`);
        const rootPrefix = params.rootRealPath.endsWith('/')
          ? params.rootRealPath
          : `${params.rootRealPath}/`;
        if (fdRealPath.endsWith(' (deleted)') || !fdRealPath.startsWith(rootPrefix)) {
          fs.closeSync(fd);
          return { ok: false, reason: 'SYMLINK_RACE' };
        }
        const postRuleCheck = evaluatePreOpen86Rules({
          candidatePath: fdRealPath,
          entryName: path.basename(fdRealPath),
          mode: params.mode,
          ntfsCaseSensitiveDir: params.ntfsCaseSensitiveDir,
          posixDevIno: postDevIno,
          rules: params.rules,
        });
        if (postRuleCheck.matched) {
          fs.closeSync(fd);
          return {
            ok: false,
            reason: 'PATH_OR_RULE_RACE',
            matchedRuleId: postRuleCheck.ruleId ?? 'R86_POST_OPEN_HIT',
          };
        }
      } catch {
        fs.closeSync(fd);
        return { ok: false, reason: 'OPEN_OR_FSTAT_ERROR' };
      }
    }

    return { ok: true, fd, fstat: fst };
  } catch {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore close error
    }
    return { ok: false, reason: 'OPEN_OR_FSTAT_ERROR' };
  }
}

/**
 * Verifies a directory before readdir() using O_DIRECTORY | O_NOFOLLOW where supported
 * and checks mount-device identity + Linux /proc/self/fd containment inside rootRealPath.
 */
function verifyDirectoryNoFollow(params: {
  dirPath: string;
  rootRealPath: string;
  rootCanonicalKey?: string;
  rootDirDev: number;
  submountPaths: Set<string>;
  ntfsCaseSensitiveDir?: boolean;
  rules?: Rule86Entry[];
}): 'OK' | 'SYMLINK' | 'MOUNT_CROSSING' | 'ERROR' {
  if (params.submountPaths.has(params.dirPath)) {
    return 'MOUNT_CROSSING';
  }

  if (process.platform === 'win32') {
    const winCheck = verifyWin32NtfsEntryNoFollow({
      targetPath: params.dirPath,
      rootCanonicalKey: params.rootCanonicalKey ?? params.rootRealPath,
      ntfsCaseSensitiveDir: params.ntfsCaseSensitiveDir,
      rules: params.rules ?? [],
      expectDirectory: true,
    });
    if (!winCheck.ok) {
      return winCheck.reason === 'REPARSE_OR_SYMLINK' ? 'SYMLINK' : 'ERROR';
    }
    if (!winCheck.meta.isDirectory) {
      return 'ERROR';
    }
    return 'OK';
  }

  const fsConsts = fs.constants as Record<string, number>;
  const oDirectory = fsConsts.O_DIRECTORY;
  if (typeof oDirectory === 'number') {
    const dirFlags =
      fs.constants.O_RDONLY |
      oDirectory |
      (fs.constants.O_NOFOLLOW ?? 0) |
      (fsConsts.O_CLOEXEC ?? 0);
    let dirFd: number | null = null;
    try {
      dirFd = fs.openSync(params.dirPath, dirFlags);
      const fst = fs.fstatSync(dirFd);
      if (!fst.isDirectory()) return 'ERROR';
      if (fst.dev !== params.rootDirDev) return 'MOUNT_CROSSING';
      if (process.platform === 'linux') {
        const realDir = fs.readlinkSync(`/proc/self/fd/${dirFd}`);
        const rootPrefix = params.rootRealPath.endsWith('/')
          ? params.rootRealPath
          : `${params.rootRealPath}/`;
        if (realDir !== params.rootRealPath && !realDir.startsWith(rootPrefix)) {
          return 'SYMLINK';
        }
      }
      return 'OK';
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'ELOOP') return 'SYMLINK';
      return 'ERROR';
    } finally {
      if (dirFd !== null) {
        try {
          fs.closeSync(dirFd);
        } catch {
          // ignore
        }
      }
    }
  }

  try {
    const st = fs.lstatSync(params.dirPath);
    if (st.isSymbolicLink()) return 'SYMLINK';
    if (!st.isDirectory()) return 'ERROR';
    if (st.dev !== params.rootDirDev) return 'MOUNT_CROSSING';
    return 'OK';
  } catch {
    return 'ERROR';
  }
}

/**
 * Inspects a .zip file's End-of-Central-Directory (EOCD) and Central Directory headers
 * strictly from the tail of the file WITHOUT inflating or reading any entry payload bytes.
 * Fails closed (quarantined=true) on encrypted entries, malformed headers, or any 86 entry match.
 */
function inspectZipCentralDirectoryHeadersOnly(
  fd: number,
  fileSize: number,
  manifest: External86Manifest
): {
  status: 'CLEAN_TOC' | 'MIXED_OR_UNCERTAIN_QUARANTINED';
  matchedRuleId?: string;
  entryCount: number;
} {
  // Minimum valid ZIP EOCD is 22 bytes
  if (fileSize < 22) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  const tailLen = Math.min(fileSize, 65557);
  const tailBuf = Buffer.alloc(tailLen);
  const bytesRead = fs.readSync(fd, tailBuf, 0, tailLen, fileSize - tailLen);
  if (bytesRead < 22) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  // Locate EOCD signature 0x06054b50 from end
  let eocdOffset = -1;
  for (let i = bytesRead - 22; i >= 0; i--) {
    if (tailBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  const totalEntries = tailBuf.readUInt16LE(eocdOffset + 10);
  const cdSize = tailBuf.readUInt32LE(eocdOffset + 12);
  const cdOffset = tailBuf.readUInt32LE(eocdOffset + 16);

  // Reject ZIP64 sentinel or out-of-bounds central directory as uncertain (fail closed)
  if (
    totalEntries === 0xffff ||
    cdSize === 0xffffffff ||
    cdOffset === 0xffffffff ||
    cdOffset + cdSize > fileSize ||
    cdSize > 16 * 1024 * 1024
  ) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  const cdBuf = Buffer.alloc(cdSize);
  const cdRead = fs.readSync(fd, cdBuf, 0, cdSize, cdOffset);
  if (cdRead !== cdSize) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: 0 };
  }

  let cursor = 0;
  let parsedEntries = 0;
  while (cursor + 46 <= cdSize && parsedEntries < totalEntries) {
    const sig = cdBuf.readUInt32LE(cursor);
    if (sig !== 0x02014b50) {
      return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
    }
    const gpBitFlag = cdBuf.readUInt16LE(cursor + 8);
    // Bit 0 = encrypted entry -> fail closed!
    if ((gpBitFlag & 0x0001) !== 0) {
      return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
    }

    const nameLen = cdBuf.readUInt16LE(cursor + 28);
    const extraLen = cdBuf.readUInt16LE(cursor + 30);
    const commentLen = cdBuf.readUInt16LE(cursor + 32);

    if (cursor + 46 + nameLen + extraLen + commentLen > cdSize) {
      return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
    }

    const entryName = cdBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString('utf8');
    const ruleHit = matchArchiveEntryAgainst86(entryName, manifest.rules);
    if (ruleHit.matched) {
      return {
        status: 'MIXED_OR_UNCERTAIN_QUARANTINED',
        matchedRuleId: ruleHit.ruleId,
        entryCount: parsedEntries,
      };
    }

    cursor += 46 + nameLen + extraLen + commentLen;
    parsedEntries += 1;
  }

  if (parsedEntries !== totalEntries) {
    return { status: 'MIXED_OR_UNCERTAIN_QUARANTINED', entryCount: parsedEntries };
  }

  return { status: 'CLEAN_TOC', entryCount: parsedEntries };
}

/**
 * Queries SQLite DDL strictly via read-only immutable URI (`mode=ro&immutable=1`)
 * so zero `-wal`, `-shm`, or `-journal` files are ever created in Zone A.
 * Uses O_NOFOLLOW + fstat verification (and /proc/self/fd/<fd> on Linux) to eliminate
 * pathname check-to-open TOCTOU races. Never executes SELECT on user data payloads.
 */
export function inspectSqliteSchemaImmutableReadOnly(
  sqlitePath: string,
  ledgerAlias: string,
  expectedStat?: Pick<fs.Stats, 'dev' | 'ino'>
): SqliteTableSchemaSummary[] | null {
  try {
    const fallbackUri = buildSqliteReadOnlyImmutableUri(sqlitePath);
    const pyScript = `
import json, os, sqlite3, stat, sys, urllib.parse
p = sys.argv[1]
exp_dev = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "" else None
exp_ino = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "" else None
fallback_uri = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != "" else "file:" + urllib.parse.quote(p) + "?mode=ro&immutable=1"
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
fd = os.open(p, flags)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
        sys.exit(11)
    if exp_dev is not None and st.st_dev != exp_dev:
        sys.exit(12)
    if exp_ino is not None and st.st_ino != exp_ino:
        sys.exit(13)
    os.lseek(fd, 0, os.SEEK_SET)
    hdr = os.read(fd, 100)
    if len(hdr) < 100 or hdr[:16] != b"SQLite format 3\\x00" or hdr[18] != 1 or hdr[19] != 1:
        sys.exit(14)
    fd_path = f"/proc/self/fd/{fd}"
    if os.path.exists(fd_path):
        uri = f"file:{fd_path}?mode=ro&immutable=1"
    else:
        uri = fallback_uri
    conn = sqlite3.connect(uri, uri=True)
    cur = conn.cursor()
    tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    out = []
    for (tname,) in tables:
        safe_ident = tname.replace('"', '""')
        cols = cur.execute(f'PRAGMA table_info("{safe_ident}")').fetchall()
        idxs = cur.execute(f'PRAGMA index_list("{safe_ident}")').fetchall()
        out.append({
            "tableName": str(tname)[:80],
            "columns": [{"name": str(c[1])[:80], "declaredType": str(c[2] or "ANY")[:40]} for c in cols],
            "indexNames": [str(ix[1])[:80] for ix in idxs],
        })
    conn.close()
    print(json.dumps(out))
finally:
    os.close(fd)
`.trim();

    const pyArgs = [
      '-c',
      pyScript,
      sqlitePath,
      expectedStat ? String(expectedStat.dev) : '',
      expectedStat ? String(expectedStat.ino) : '',
      fallbackUri,
    ];

    const stdout = execFileSync('python3', pyArgs, {
      encoding: 'utf8',
      timeout: 4000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const parsed = JSON.parse(stdout) as Array<{
      tableName: string;
      columns: Array<{ name: string; declaredType: string }>;
      indexNames: string[];
    }>;

    return parsed.map((t) => ({
      ledgerAlias,
      tableName: t.tableName,
      columns: t.columns,
      indexNames: t.indexNames,
      approximateRowCount: null, // Deliberately omitted to avoid reading table b-tree data pages
      openedImmutableReadOnly: true,
    }));
  } catch {
    return null;
  }
}

/**
 * Structural-only header signature sniffer (<= 2048 bytes read, immediately discarded).
 * Identifies likely vendor format from structural JSON keys WITHOUT retaining any text values.
 */
function classifyHeaderSignatureOnly(
  headerSlice: string,
  ext: string
): {
  ecosystem: VendorEcosystemId;
  hasExplicitEventTimestamps: boolean | 'UNKNOWN';
} {
  const hasSubagentKeys =
    headerSlice.includes('"subagent_id"') ||
    headerSlice.includes('"parent_agent_id"') ||
    headerSlice.includes('"antigravity"');
  if (hasSubagentKeys) {
    return {
      ecosystem: 'antigravity',
      hasExplicitEventTimestamps:
        headerSlice.includes('"timestamp"') || headerSlice.includes('"created_at"'),
    };
  }

  if (
    headerSlice.includes('"parentUuid"') &&
    (headerSlice.includes('"cwd"') || headerSlice.includes('"toolUseResult"'))
  ) {
    return {
      ecosystem: 'claude_code',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"'),
    };
  }

  if (
    headerSlice.includes('"codex"') ||
    (ext === '.jsonl' &&
      headerSlice.includes('"call_id"') &&
      headerSlice.includes('"type":"function_call"'))
  ) {
    return {
      ecosystem: 'codex_cli',
      hasExplicitEventTimestamps:
        headerSlice.includes('"timestamp"') || headerSlice.includes('"created_at"'),
    };
  }

  if (
    headerSlice.includes('"gemini_cli"') ||
    (headerSlice.includes('"sessionId"') && headerSlice.includes('"thoughts"'))
  ) {
    return {
      ecosystem: 'gemini_cli',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"'),
    };
  }

  if (headerSlice.includes('"mapping"') && headerSlice.includes('"current_node"')) {
    return {
      ecosystem: 'chatgpt_openai',
      hasExplicitEventTimestamps: headerSlice.includes('"create_time"'),
    };
  }

  if (headerSlice.includes('"chat_messages"') && headerSlice.includes('"sender"')) {
    return {
      ecosystem: 'claude_web',
      hasExplicitEventTimestamps: headerSlice.includes('"created_at"'),
    };
  }

  if (headerSlice.includes('"reasoning_content"')) {
    return {
      ecosystem: 'deepseek',
      hasExplicitEventTimestamps:
        headerSlice.includes('"inserted_at"') || headerSlice.includes('"created_at"'),
    };
  }

  if (headerSlice.includes('"task_steps"') && headerSlice.includes('"manus"')) {
    return {
      ecosystem: 'manus',
      hasExplicitEventTimestamps: headerSlice.includes('"timestamp"'),
    };
  }

  if (headerSlice.includes('"grok"') && headerSlice.includes('"conversations"')) {
    return {
      ecosystem: 'grok',
      hasExplicitEventTimestamps: headerSlice.includes('"create_time"'),
    };
  }

  if (headerSlice.includes('"gemini"') && headerSlice.includes('"parts"')) {
    return {
      ecosystem: 'gemini_web',
      hasExplicitEventTimestamps: 'UNKNOWN',
    };
  }

  return {
    ecosystem: 'unknown_structured',
    hasExplicitEventTimestamps: 'UNKNOWN',
  };
}

function binaryExistsInPath(binName: string): boolean {
  try {
    const checker = process.platform === 'win32' ? 'where' : 'which';
    execFileSync(checker, [binName], { stdio: 'ignore', timeout: 1500 });
    return true;
  } catch {
    return false;
  }
}

function probeNvidiaGpus(): SanitizedStage0Report['hostProfile']['gpuSummary'] {
  try {
    const out = execFileSync(
      'nvidia-smi',
      ['--query-gpu=name,memory.total,memory.free', '--format=csv,noheader,nounits'],
      { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const devices = out
      .trim()
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const [name, total, free] = line.split(',').map((s) => s.trim());
        return {
          modelCode: String(name || 'GPU').slice(0, 64),
          vramTotalMb: Number(total) || 0,
          vramFreeMb: Number(free) || 0,
        };
      });
    return {
      detectionState: devices.length > 0 ? 'DETECTED' : 'NONE_DETECTED',
      devices,
    };
  } catch {
    return { detectionState: 'NONE_DETECTED', devices: [] };
  }
}

/**
 * Safely writes the already-sanitized Stage 0 report strictly into Zone B without following
 * a symlink at the destination filename.
 */
function writeZoneBReportNoFollow(zoneBOutputDir: string, serializedReportJson: string): string {
  if (fs.existsSync(zoneBOutputDir)) {
    const dirSt = fs.lstatSync(zoneBOutputDir);
    if (dirSt.isSymbolicLink() || !dirSt.isDirectory()) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_FS',
        'ZONE_B_OUTPUT_DIR_SYMLINK_OR_NON_DIR',
        'Refusing to write Stage 0 report: Zone B output directory is a symlink or non-directory.'
      );
    }
  } else {
    fs.mkdirSync(zoneBOutputDir, { recursive: true });
  }

  if (process.platform === 'win32') {
    const dirMeta = inspectWin32NtfsHandleNoFollow(zoneBOutputDir);
    if (
      !dirMeta.available ||
      dirMeta.isReparsePoint ||
      dirMeta.isCloudHydrationHazard ||
      !dirMeta.isDirectory
    ) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_FS',
        'ZONE_B_WIN32_UNSAFE',
        'Refusing to write Stage 0 report: Zone B output directory failed Win32 NTFS safety verification.'
      );
    }
  }

  const outPath = path.join(zoneBOutputDir, 'stage0-sanitized-report.json');
  if (process.platform === 'win32') {
    let outExists = false;
    try {
      fs.lstatSync(outPath);
      outExists = true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT') {
        throw new Stage0FailClosedError(
          'FAIL_CLOSED_FS',
          'ZONE_B_WIN32_UNSAFE',
          'Refusing to write Stage 0 report: unable to lstat Zone B target path on Win32.'
        );
      }
    }
    if (outExists) {
      const outMeta = inspectWin32NtfsHandleNoFollow(outPath);
      if (
        !outMeta.available ||
        outMeta.isReparsePoint ||
        outMeta.isCloudHydrationHazard ||
        outMeta.isDirectory ||
        outMeta.nNumberOfLinks > 1
      ) {
        throw new Stage0FailClosedError(
          'FAIL_CLOSED_FS',
          'ZONE_B_WIN32_UNSAFE',
          'Refusing to write Stage 0 report: Zone B target file failed Win32 NTFS safety verification.'
        );
      }
    }
  }
  const fsConsts = fs.constants as Record<string, number>;
  const writeFlags =
    fs.constants.O_WRONLY |
    fs.constants.O_CREAT |
    fs.constants.O_TRUNC |
    (fs.constants.O_NOFOLLOW ?? 0) |
    (fsConsts.O_CLOEXEC ?? 0);

  let fd: number | null = null;
  try {
    fd = fs.openSync(outPath, writeFlags, 0o600);
    const fst = fs.fstatSync(fd);
    if (!fst.isFile() || fst.nlink > 1) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_FS',
        'ZONE_B_REPORT_TARGET_UNSAFE',
        'Refusing to write Stage 0 report to non-regular or hardlinked target in Zone B.'
      );
    }
    fs.writeFileSync(fd, serializedReportJson, 'utf8');
  } catch (err) {
    if (err instanceof Stage0FailClosedError) throw err;
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_FS',
      'ZONE_B_REPORT_WRITE_FAILED',
      `Failed to write sanitized Stage 0 report to Zone B: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
  return outPath;
}

export interface ExecuteStage0Options {
  config: Stage0Config;
  manifestRawJson: string;
  /**
   * Independently trusted 64-character hex SHA-256 digest of the external 86 manifest.
   * Required (either here or via config.expectedExternal86ManifestSha256). If both are provided,
   * BOTH must match the manifest bytes via timing-safe comparison.
   */
  expectedManifestSha256?: string;
  evidenceOrigin: SanitizedStage0Report['evidenceOrigin'];
  canaryResults?: MultiIdentityCanaryResult[];
  writeReportFileToZoneB?: boolean;
}

export function executeStage0Discovery(options: ExecuteStage0Options): {
  report: SanitizedStage0Report;
  serializedReportJson: string;
  telemetry: TraversalTelemetry;
  writtenReportPath?: string;
} {
  const telemetry: TraversalTelemetry = {
    readdirCalls: 0,
    lstatCalls: 0,
    openCalls: 0,
    openedPaths: [],
  };

  // Precondition Step 1: Authenticate external 86 manifest SHA-256 against an independently
  // trusted expected digest BEFORE parsing the manifest or touching any scan root.
  const primaryExpectedSha256 =
    options.expectedManifestSha256 ?? options.config?.expectedExternal86ManifestSha256;
  const secondaryExpectedSha256 =
    options.expectedManifestSha256 && options.config?.expectedExternal86ManifestSha256
      ? options.config.expectedExternal86ManifestSha256
      : undefined;

  const manifestSha256 = verifyManifestSha256(
    options.manifestRawJson,
    primaryExpectedSha256,
    secondaryExpectedSha256
  );

  let manifest: External86Manifest;
  try {
    manifest = JSON.parse(options.manifestRawJson) as External86Manifest;
  } catch {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'MANIFEST_JSON_PARSE_ERROR',
      'External 86 manifest is not valid JSON; failing closed before traversal.'
    );
  }

  // Precondition Step 2: Validate scan_roots_allowlist, Zone B disjointness, and 86 rules
  const { normalizedRoots } = validateStage0Preconditions(options.config, manifest);

  // Build fast lookup sets for hardlink inode protection & conversation-level mixed container checks
  const revokedPosixDevInos = new Set<string>(
    manifest.rules
      .filter((r) => r.kind === 'POSIX_DEV_INO')
      .map((r) => r.targetValue)
  );
  const hasConversationLevel86Rules = manifest.rules.some(
    (r) => r.kind === 'REVOKED_CONVERSATION_ID'
  );
  const hasArchiveEntry86Rules = manifest.rules.some(
    (r) => r.kind === 'ARCHIVE_ENTRY_NAME'
  );

  const pruned86ByRuleId: Record<string, number> = {};
  const record86Hit = (ruleId: string) => {
    const safeKey = /^[A-Za-z0-9_-]{2,40}$/.test(ruleId)
      ? ruleId
      : 'OPAQUE_RULE_HIT';
    pruned86ByRuleId[safeKey] = (pruned86ByRuleId[safeKey] ?? 0) + 1;
  };

  let reparseOrSymlinkSkippedCount = 0;
  let mountCrossingSkippedCount = 0;
  let hardlinkAliasBlockedCount = 0;
  let cloudPlaceholderSkippedCount = 0;
  let mixedContainerQuarantinedCount = 0;
  let potentialMixedUnscannedCount = 0;
  let failClosedUncertainCount = 0;
  let ggufHeaderCount = 0;

  const recordOpenFailure = (failed: Extract<SafeOpenResult, { ok: false }>): void => {
    if (failed.reason === 'SYMLINK_RACE') {
      reparseOrSymlinkSkippedCount += 1;
    } else if (failed.reason === 'HARDLINK_RACE') {
      hardlinkAliasBlockedCount += 1;
    } else if (failed.reason === 'CLOUD_PLACEHOLDER') {
      cloudPlaceholderSkippedCount += 1;
    } else if (
      failed.reason === 'REVOKED_INODE_RACE' ||
      failed.reason === 'PATH_OR_RULE_RACE'
    ) {
      record86Hit(failed.matchedRuleId ?? 'R86_RACE_HIT');
    } else {
      failClosedUncertainCount += 1;
    }
  };

  const sqliteSchemas: SqliteTableSchemaSummary[] = [];
  let sqliteIdx = 1;

  const formatMap = new Map<
    VendorEcosystemId,
    {
      files: number;
      bytes: number;
      containers: number;
      hasTimestamps: boolean | 'UNKNOWN';
      mixedRisks: number;
    }
  >();
  for (const eco of ALL_ECOSYSTEMS) {
    formatMap.set(eco, {
      files: 0,
      bytes: 0,
      containers: 0,
      hasTimestamps: 'UNKNOWN',
      mixedRisks: 0,
    });
  }

  // Step 3: Walk ONLY allowlisted roots using lstat + O_NOFOLLOW + fstat verification
  for (const root of normalizedRoots) {
    telemetry.lstatCalls += 1;
    let rootStat: fs.Stats;
    try {
      rootStat = fs.lstatSync(root.absolutePath);
    } catch {
      failClosedUncertainCount += 1;
      continue;
    }

    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
      // Never traverse a scan root that is itself a symlink/reparse point or non-directory
      reparseOrSymlinkSkippedCount += 1;
      continue;
    }

    let rootRealPath: string;
    try {
      rootRealPath = fs.realpathSync(root.absolutePath);
    } catch {
      failClosedUncertainCount += 1;
      continue;
    }

    const rootDirDev = rootStat.dev;
    // Also inspect /proc/self/mountinfo on Linux to catch both directory and single-file bind mounts
    // without false positives on overlayfs (where upperdir files and overlay dirs have distinct st_dev).
    const submountPaths = new Set<string>();
    try {
      if (fs.existsSync('/proc/self/mountinfo')) {
        const minfo = fs.readFileSync('/proc/self/mountinfo', 'utf8');
        const rootPrefix = rootRealPath.endsWith('/') ? rootRealPath : `${rootRealPath}/`;
        for (const line of minfo.split('\n')) {
          const parts = line.split(' ');
          if (parts.length >= 5) {
            const mountPoint = parts[4].replace(/\\040/g, ' ');
            if (mountPoint.startsWith(rootPrefix)) {
              submountPaths.add(mountPoint);
            }
          }
        }
      }
    } catch {
      // Non-Linux host; directory st_dev check still applies
    }

    const queue: string[] = [root.absolutePath];

    while (queue.length > 0) {
      const currentDir = queue.shift()!;

      // Check directory against 86 rules BEFORE readdir
      const dirPreCheck = evaluatePreOpen86Rules({
        candidatePath: currentDir,
        entryName: path.basename(currentDir),
        mode: root.expectedFsMode,
        ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
        rules: manifest.rules,
      });
      if (dirPreCheck.matched) {
        record86Hit(dirPreCheck.ruleId ?? 'R86_DIR_HIT');
        continue;
      }

      // Verify directory handle with O_DIRECTORY | O_NOFOLLOW before readdir
      const dirStatus = verifyDirectoryNoFollow({
        dirPath: currentDir,
        rootRealPath,
        rootCanonicalKey: root.canonicalKey,
        rootDirDev,
        submountPaths,
        ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
        rules: manifest.rules,
      });
      if (dirStatus === 'SYMLINK') {
        reparseOrSymlinkSkippedCount += 1;
        continue;
      }
      if (dirStatus === 'MOUNT_CROSSING') {
        mountCrossingSkippedCount += 1;
        continue;
      }
      if (dirStatus === 'ERROR') {
        failClosedUncertainCount += 1;
        continue;
      }

      let entries: string[];
      try {
        telemetry.readdirCalls += 1;
        entries = fs.readdirSync(currentDir);
      } catch {
        // EACCES / EPERM / uncertain directory permissions -> fail closed immediately!
        failClosedUncertainCount += 1;
        continue;
      }

      for (const entryName of entries) {
        const fullPath = path.join(currentDir, entryName);

        // Stage-0 Barrier Step A: Path/name/glob/conv-id/mixed-container check BEFORE lstat/open
        const nameGate = evaluatePreOpen86Rules({
          candidatePath: fullPath,
          entryName,
          mode: root.expectedFsMode,
          ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
          rules: manifest.rules,
        });
        if (nameGate.matched) {
          if (nameGate.matchedKind === 'KNOWN_MIXED_CONTAINER') {
            mixedContainerQuarantinedCount += 1;
          }
          record86Hit(nameGate.ruleId ?? 'R86_PATH_HIT');
          continue;
        }

        // Stage-0 Barrier Step B: Non-following lstat()
        let st: fs.Stats;
        try {
          telemetry.lstatCalls += 1;
          st = fs.lstatSync(fullPath);
        } catch {
          failClosedUncertainCount += 1;
          continue;
        }

        // Never follow symlinks / reparse links
        if (st.isSymbolicLink()) {
          reparseOrSymlinkSkippedCount += 1;
          continue;
        }

        // Block unexpected mount-point / bind-mount crossings
        if (submountPaths.has(fullPath) || (st.isDirectory() && st.dev !== rootDirDev)) {
          mountCrossingSkippedCount += 1;
          continue;
        }

        if (process.platform === 'win32') {
          const winEntry = verifyWin32NtfsEntryNoFollow({
            targetPath: fullPath,
            rootCanonicalKey: root.canonicalKey,
            ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
            rules: manifest.rules,
            expectDirectory: st.isDirectory(),
          });
          if (!winEntry.ok) {
            if (winEntry.reason === 'CLOUD_PLACEHOLDER') {
              cloudPlaceholderSkippedCount += 1;
            } else if (winEntry.reason === 'REPARSE_OR_SYMLINK') {
              reparseOrSymlinkSkippedCount += 1;
            } else if (winEntry.reason === 'HARDLINK') {
              hardlinkAliasBlockedCount += 1;
            } else if (
              winEntry.reason === 'REVOKED_NTFS_FILE_ID' ||
              (winEntry.reason === 'PATH_ESCAPE_OR_86' && winEntry.matchedRuleId)
            ) {
              record86Hit(winEntry.matchedRuleId ?? 'R86_WIN32_HIT');
            } else {
              failClosedUncertainCount += 1;
            }
            continue;
          }
        }

        const posixDevIno = `${st.dev}:${st.ino}`;

        // Block hardlink aliases pointing to an 86'd (dev, ino)
        if (revokedPosixDevInos.has(posixDevIno)) {
          if (st.nlink > 1) {
            hardlinkAliasBlockedCount += 1;
          }
          const inoHit = evaluatePreOpen86Rules({
            candidatePath: fullPath,
            entryName,
            mode: root.expectedFsMode,
            posixDevIno,
            rules: manifest.rules,
          });
          record86Hit(inoHit.ruleId ?? 'R86_INODE_HIT');
          continue;
        }

        // Fail closed if hardlink count > 1 and identity could alias outside scan root
        if (st.isFile() && st.nlink > 1) {
          hardlinkAliasBlockedCount += 1;
          continue;
        }

        if (st.isDirectory()) {
          queue.push(fullPath);
          continue;
        }

        if (!st.isFile()) {
          // FIFOs, sockets, device nodes -> skip safely
          failClosedUncertainCount += 1;
          continue;
        }

        // Check owner read bit before attempting open; fail closed if unreadable
        if ((st.mode & 0o444) === 0) {
          failClosedUncertainCount += 1;
          continue;
        }

        const ext = path.extname(entryName).toLowerCase();

        if (ext === '.gguf') {
          ggufHeaderCount += 1;
          continue;
        }

        // Mixed-Container Rule 1: ZIP archives — inspect Central Directory headers ONLY via verified O_NOFOLLOW fd
        if (ext === '.zip') {
          telemetry.openCalls += 1;
          telemetry.openedPaths.push(fullPath);
          const opened = openRegularFileNoFollowVerified({
            fullPath,
            entryName,
            expectedStat: st,
            rootRealPath,
            rootCanonicalKey: root.canonicalKey,
            mode: root.expectedFsMode,
            ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
            revokedPosixDevInos,
            rules: manifest.rules,
          });
          if (!opened.ok) {
            recordOpenFailure(opened);
            continue;
          }
          try {
            const zipRes = inspectZipCentralDirectoryHeadersOnly(
              opened.fd,
              opened.fstat.size,
              manifest
            );
            if (zipRes.status === 'MIXED_OR_UNCERTAIN_QUARANTINED') {
              mixedContainerQuarantinedCount += 1;
              if (zipRes.matchedRuleId) {
                record86Hit(zipRes.matchedRuleId);
              }
            }
          } catch {
            failClosedUncertainCount += 1;
          } finally {
            fs.closeSync(opened.fd);
          }
          continue;
        }

        // Mixed-Container Rule 1b: Non-ZIP archives cannot be TOC-checked header-only -> quarantine unscanned
        if (UNSCANNABLE_ARCHIVE_EXTS.has(ext) && (hasConversationLevel86Rules || hasArchiveEntry86Rules)) {
          potentialMixedUnscannedCount += 1;
          continue;
        }

        // Mixed-Container Rule 2: SQLite ledgers
        // When conversation-level 86 rules exist, fail closed and quarantine UNSCANNED (zero opens, zero DDL reads).
        // Only when no conversation-level 86 rules exist, open via O_NOFOLLOW + verify header/sidecars before immutable DDL read.
        if (ext === '.sqlite' || ext === '.sqlite3' || ext === '.db') {
          if (hasConversationLevel86Rules) {
            potentialMixedUnscannedCount += 1;
            continue;
          }
          telemetry.openCalls += 1;
          telemetry.openedPaths.push(fullPath);
          const opened = openRegularFileNoFollowVerified({
            fullPath,
            entryName,
            expectedStat: st,
            rootRealPath,
            rootCanonicalKey: root.canonicalKey,
            mode: root.expectedFsMode,
            ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
            revokedPosixDevInos,
            rules: manifest.rules,
          });
          if (!opened.ok) {
            recordOpenFailure(opened);
            continue;
          }
          let sqliteSafe = false;
          let expectedOpenedStat: Pick<fs.Stats, 'dev' | 'ino'> | null = null;
          try {
            const sqliteCheck = checkSqliteSafeForImmutableInspection(opened.fd, fullPath);
            if (!sqliteCheck.safeForImmutableDdlInspection) {
              if (
                sqliteCheck.quarantineReason === 'SQLITE_WAL_MODE_HEADER' ||
                sqliteCheck.quarantineReason === 'SQLITE_WAL_SIDECAR_PRESENT' ||
                sqliteCheck.quarantineReason === 'SQLITE_SHM_SIDECAR_PRESENT' ||
                sqliteCheck.quarantineReason === 'SQLITE_HOT_JOURNAL_PRESENT'
              ) {
                potentialMixedUnscannedCount += 1;
              } else {
                failClosedUncertainCount += 1;
              }
              continue;
            }
            sqliteSafe = true;
            expectedOpenedStat = {
              dev: opened.fstat.dev,
              ino: opened.fstat.ino,
            };
          } finally {
            fs.closeSync(opened.fd);
          }

          if (!sqliteSafe || !expectedOpenedStat) {
            continue;
          }

          const alias = `LEDGER_${String(sqliteIdx).padStart(2, '0')}`;
          sqliteIdx += 1;
          const ddl = inspectSqliteSchemaImmutableReadOnly(
            fullPath,
            alias,
            expectedOpenedStat
          );
          if (ddl === null) {
            failClosedUncertainCount += 1;
          } else {
            sqliteSchemas.push(...ddl);
          }
          continue;
        }

        // Mixed-Container Rule 3: Monolithic multi-conversation JSON when conversation-level 86 IDs exist
        const lowerName = entryName.toLowerCase();
        const looksMonolithicMultiConv =
          lowerName === 'conversations.json' ||
          lowerName.includes('export') ||
          lowerName.includes('takeout');
        if (hasConversationLevel86Rules && looksMonolithicMultiConv) {
          potentialMixedUnscannedCount += 1;
          const chatgptSlot = formatMap.get('chatgpt_openai')!;
          chatgptSlot.mixedRisks += 1;
          continue;
        }

        // Cleared structured JSON / JSONL file: open with O_NOFOLLOW + fstat verification,
        // then read <= 2048-byte header slice ONLY for structural keys.
        if (ext === '.json' || ext === '.jsonl') {
          telemetry.openCalls += 1;
          telemetry.openedPaths.push(fullPath);
          const opened = openRegularFileNoFollowVerified({
            fullPath,
            entryName,
            expectedStat: st,
            rootRealPath,
            rootCanonicalKey: root.canonicalKey,
            mode: root.expectedFsMode,
            ntfsCaseSensitiveDir: root.ntfsCaseSensitiveDir,
            revokedPosixDevInos,
            rules: manifest.rules,
          });
          if (!opened.ok) {
            recordOpenFailure(opened);
            continue;
          }
          try {
            const sliceLen = Math.min(opened.fstat.size, 2048);
            const buf = Buffer.alloc(sliceLen);
            const readBytes = fs.readSync(opened.fd, buf, 0, sliceLen, 0);
            const headerStr = buf.subarray(0, readBytes).toString('utf8');
            const sig = classifyHeaderSignatureOnly(headerStr, ext);
            const bucket = formatMap.get(sig.ecosystem)!;
            bucket.files += 1;
            bucket.bytes += opened.fstat.size;
            bucket.containers += 1;
            if (sig.hasExplicitEventTimestamps !== 'UNKNOWN') {
              bucket.hasTimestamps = sig.hasExplicitEventTimestamps;
            }
          } catch {
            failClosedUncertainCount += 1;
          } finally {
            fs.closeSync(opened.fd);
          }
        }
      }
    }
  }

  // Probe optional Universal Harness paths (existence & entrypoint count only, read-only, 86-checked)
  let universalHarnessDetected = false;
  let universalHarnessEntrypointsCount = 0;
  for (const hp of options.config.universalHarnessProbePaths ?? []) {
    const preCheck = evaluatePreOpen86Rules({
      candidatePath: hp,
      entryName: path.basename(hp),
      mode: options.config.hostOsMode,
      rules: manifest.rules,
    });
    if (preCheck.matched) {
      continue;
    }
    try {
      const hStat = fs.lstatSync(hp);
      if (!hStat.isSymbolicLink() && (hStat.isDirectory() || hStat.isFile())) {
        universalHarnessDetected = true;
        universalHarnessEntrypointsCount += 1;
      }
    } catch {
      // Not present
    }
  }

  const formatInventory: FormatInventoryRecord[] = ALL_ECOSYSTEMS.map((eco) => {
    const b = formatMap.get(eco)!;
    return {
      ecosystem: eco,
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: b.files,
      nonQuarantinedBytes: b.bytes,
      estimatedContainerCount: b.containers,
      hasExplicitEventTimestamps: b.hasTimestamps,
      mixedArchiveRiskCount: b.mixedRisks,
      existingHarnessReuseDetected:
        universalHarnessDetected &&
        (eco === 'antigravity' || eco === 'gemini_cli' || eco === 'codex_cli'),
    };
  });

  const reuseAssessmentCode: SanitizedStage0Report['reuseInventory']['reuseAssessmentCode'] =
    options.evidenceOrigin === 'UNINSPECTED_NO_REPORT'
      ? 'PENDING_WORKSTATION_EVIDENCE'
      : universalHarnessDetected
        ? 'CANDIDATE_HARNESS_EXTENSION'
        : sqliteSchemas.length > 0
          ? 'CANDIDATE_MODULAR_COMPANION'
          : 'CANDIDATE_MINIMAL_CORE';

  const report: SanitizedStage0Report = {
    schemaVersion: '1.0.0',
    stage: 'STAGE_0_READ_ONLY_DISCOVERY',
    evidenceOrigin: options.evidenceOrigin,
    generatedAtIso: new Date().toISOString(),
    hostProfile: {
      osPlatform: os.platform(),
      osRelease: os.release().slice(0, 48),
      cpuCores: os.cpus().length,
      totalMemBytes: os.totalmem(),
      freeMemBytes: os.freemem(),
      gpuSummary: probeNvidiaGpus(),
      llamaCppStatus: {
        serverBinaryPresent: binaryExistsInPath('llama-server'),
        cliBinaryPresent: binaryExistsInPath('llama-cli'),
        versionTag: 'NONE_DETECTED',
        ggufHeaderCount,
      },
      gcloudCliPresent: binaryExistsInPath('gcloud'),
      rootFilesystems: normalizedRoots.map((r) => ({
        rootAlias: r.alias,
        fsMode: r.expectedFsMode,
      })),
    },
    securityAudit: {
      allowlistRootCount: normalizedRoots.length,
      manifestId: manifest.manifestId,
      manifestSha256,
      manifestIntegrityVerified: true,
      pruned86ByRuleId,
      reparseOrSymlinkSkippedCount,
      mountCrossingSkippedCount,
      hardlinkAliasBlockedCount,
      cloudPlaceholderSkippedCount,
      mixedContainerQuarantinedCount,
      potentialMixedUnscannedCount,
      failClosedUncertainCount,
      zoneAWriteViolations: 0,
      multiIdentityCanaryResults: options.canaryResults ?? [],
    },
    reuseInventory: {
      universalHarnessDetected,
      universalHarnessEntrypointsCount,
      sqliteLedgersInspected: sqliteSchemas,
      reuseAssessmentCode,
    },
    formatInventory,
  };

  // Pre-emit zero-leak sanitization check (authoritative across both sandbox and exported workstation runner)
  const serializedReportJson = assertSanitizedStage0Report(report);

  let writtenReportPath: string | undefined;
  if (options.writeReportFileToZoneB) {
    writtenReportPath = writeZoneBReportNoFollow(
      options.config.zoneBOutputDir,
      serializedReportJson
    );
  }

  return {
    report,
    serializedReportJson,
    telemetry,
    writtenReportPath,
  };
}
