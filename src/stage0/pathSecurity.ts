import crypto from 'node:crypto';
import path from 'node:path';
import type {
  External86Manifest,
  FailClosedCode,
  OsPlatformMode,
  Rule86Entry,
  ScanRootEntry,
  Stage0Config,
} from './types.ts';

export class Stage0FailClosedError extends Error {
  readonly code: FailClosedCode;
  readonly detailCode: string;

  constructor(code: FailClosedCode, detailCode: string, message: string) {
    super(message);
    this.name = 'Stage0FailClosedError';
    this.code = code;
    this.detailCode = detailCode;
  }
}

const WIN32_RESERVED_BASENAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'CLOCK$',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
]);

// Windows file attribute & reparse constants for native Win32 / DrvFS / manifest metadata checks
export const WIN32_ATTR_REPARSE_POINT = 0x00000400;
export const WIN32_ATTR_OFFLINE = 0x00001000;
export const WIN32_ATTR_RECALL_ON_OPEN = 0x00040000;
export const WIN32_ATTR_RECALL_ON_DATA_ACCESS = 0x00400000;

export const REPARSE_TAG_MOUNT_POINT = 0xa0000003; // NTFS Directory Junction / Volume Mount
export const REPARSE_TAG_SYMLINK = 0xa000000c;
export const REPARSE_TAG_CLOUD = 0x9000001a;
export const REPARSE_TAG_CLOUD_1 = 0x9000101a;
export const REPARSE_TAG_WSL = 0xa000001d;

export interface PathNormalizationResult {
  ok: boolean;
  canonicalComparisonKey: string;
  displayNormalizedPath: string;
  extendedWin32Path?: string;
  hazardReason?: string;
}

/**
 * Windows NTFS Path Normalization & Hazard Specification:
 * - Rejects NUL/control bytes, UNC/SMB shares (\\server\share, \\?\UNC\...),
 *   NTFS Alternate Data Streams (file:stream:$DATA), trailing dots/spaces on segments,
 *   and Win32 reserved device names (CON, NUL, COM1, CON.txt, etc.).
 * - Normalizes to Unicode NFC and extended-length \\?\C:\... form.
 * - Case-folds for comparison UNLESS directory carries FILE_CS_FLAG_CASE_SENSITIVE_DIR.
 */
export function normalizeWindowsNtfsPath(
  rawInput: string,
  caseSensitiveDir = false
): PathNormalizationResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'EMPTY_NTFS_PATH',
    };
  }

  for (let i = 0; i < rawInput.length; i++) {
    const code = rawInput.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return {
        ok: false,
        canonicalComparisonKey: '',
        displayNormalizedPath: '',
        hazardReason: 'NTFS_CONTROL_OR_NUL_CHAR',
      };
    }
  }

  const nfc = rawInput.normalize('NFC');
  let working = nfc.replace(/\//g, '\\');

  // Block UNC / SMB network shares explicitly
  const upper = working.toUpperCase();
  if (
    upper.startsWith('\\\\?\\UNC\\') ||
    (working.startsWith('\\\\') && !working.startsWith('\\\\?\\'))
  ) {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'NTFS_UNC_OR_NETWORK_SHARE_FORBIDDEN',
    };
  }

  // Strip extended-length prefix temporarily to inspect drive & segments cleanly
  if (working.startsWith('\\\\?\\')) {
    working = working.slice(4);
  }

  // Must start with standard drive letter C:\...
  if (!/^[A-Za-z]:(\\|$)/.test(working)) {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'NTFS_NON_ABSOLUTE_OR_MISSING_DRIVE',
    };
  }

  const driveLetter = working[0].toUpperCase();
  const rest = working.slice(2);

  // Reject NTFS Alternate Data Streams (colon anywhere after drive specifier C:)
  if (rest.includes(':')) {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'NTFS_ALTERNATE_DATA_STREAM_FORBIDDEN',
    };
  }

  const rawSegments = rest.split('\\').filter((s) => s.length > 0);
  const resolvedSegments: string[] = [];

  for (const seg of rawSegments) {
    if (seg === '.') {
      continue;
    }
    if (seg === '..') {
      // Do not allow .. to escape drive root or traverse blindly in raw config
      return {
        ok: false,
        canonicalComparisonKey: '',
        displayNormalizedPath: '',
        hazardReason: 'NTFS_DOTDOT_TRAVERSAL_FORBIDDEN',
      };
    }
    // Trailing dot or space is silently stripped by Win32 APIs, causing canonicalization bypasses
    if (seg.endsWith('.') || seg.endsWith(' ')) {
      return {
        ok: false,
        canonicalComparisonKey: '',
        displayNormalizedPath: '',
        hazardReason: 'NTFS_TRAILING_DOT_OR_SPACE_HAZARD',
      };
    }

    // Check Win32 reserved device names (e.g., CON, NUL.json, COM1.log)
    const stem = seg.split('.')[0].toUpperCase();
    if (WIN32_RESERVED_BASENAMES.has(stem)) {
      return {
        ok: false,
        canonicalComparisonKey: '',
        displayNormalizedPath: '',
        hazardReason: `NTFS_RESERVED_DEVICE_NAME:${stem}`,
      };
    }

    resolvedSegments.push(seg);
  }

  const normalizedWin =
    resolvedSegments.length === 0
      ? `${driveLetter}:\\`
      : `${driveLetter}:\\${resolvedSegments.join('\\')}`;
  const extendedWin32Path = `\\\\?\\${normalizedWin}`;
  const canonicalComparisonKey = caseSensitiveDir
    ? normalizedWin
    : normalizedWin.toLowerCase();

  return {
    ok: true,
    canonicalComparisonKey,
    displayNormalizedPath: normalizedWin,
    extendedWin32Path,
  };
}

/**
 * POSIX Path Normalization & Hazard Specification:
 * - Rejects NUL bytes, control chars, relative paths, and '..' segments in untrusted paths.
 * - Preserves exact case sensitivity of POSIX byte paths.
 */
export function normalizePosixPath(rawInput: string): PathNormalizationResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'EMPTY_POSIX_PATH',
    };
  }

  for (let i = 0; i < rawInput.length; i++) {
    const code = rawInput.charCodeAt(i);
    if (code === 0 || code < 0x20 || code === 0x7f) {
      return {
        ok: false,
        canonicalComparisonKey: '',
        displayNormalizedPath: '',
        hazardReason: 'POSIX_NUL_OR_CONTROL_CHAR',
      };
    }
  }

  if (!rawInput.startsWith('/')) {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'POSIX_RELATIVE_PATH_FORBIDDEN',
    };
  }

  const rawSegments = rawInput.split('/');
  const cleanSegments: string[] = [];
  for (const seg of rawSegments) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      return {
        ok: false,
        canonicalComparisonKey: '',
        displayNormalizedPath: '',
        hazardReason: 'POSIX_DOTDOT_TRAVERSAL_FORBIDDEN',
      };
    }
    cleanSegments.push(seg);
  }

  const normalized = '/' + cleanSegments.join('/');

  // Block dangerous OS pseudo-filesystems as scan roots
  if (
    normalized === '/' ||
    normalized === '/proc' ||
    normalized.startsWith('/proc/') ||
    normalized === '/sys' ||
    normalized.startsWith('/sys/') ||
    normalized === '/dev' ||
    normalized.startsWith('/dev/')
  ) {
    return {
      ok: false,
      canonicalComparisonKey: '',
      displayNormalizedPath: '',
      hazardReason: 'POSIX_FORBIDDEN_ROOT_OR_PSEUDO_FS',
    };
  }

  return {
    ok: true,
    canonicalComparisonKey: normalized,
    displayNormalizedPath: normalized,
  };
}

export function normalizePathByMode(
  rawPath: string,
  mode: OsPlatformMode,
  ntfsCaseSensitive = false
): PathNormalizationResult {
  return mode === 'WINDOWS_NTFS'
    ? normalizeWindowsNtfsPath(rawPath, ntfsCaseSensitive)
    : normalizePosixPath(rawPath);
}

export function pathsOverlap(
  keyA: string,
  keyB: string,
  mode: OsPlatformMode
): boolean {
  const sep = mode === 'WINDOWS_NTFS' ? '\\' : '/';
  const trimA = keyA.length > 3 && keyA.endsWith(sep) ? keyA.slice(0, -1) : keyA;
  const trimB = keyB.length > 3 && keyB.endsWith(sep) ? keyB.slice(0, -1) : keyB;
  if (trimA === trimB) return true;
  if (trimA.startsWith(trimB + sep)) return true;
  if (trimB.startsWith(trimA + sep)) return true;
  return false;
}

export function classifyWin32AttributesAndReparse(
  dwFileAttributes: number,
  reparseTag?: number
): {
  isReparsePoint: boolean;
  isCloudHydrationHazard: boolean;
  reparseClassification: string | null;
} {
  const isCloudHydrationHazard =
    (dwFileAttributes & WIN32_ATTR_OFFLINE) !== 0 ||
    (dwFileAttributes & WIN32_ATTR_RECALL_ON_OPEN) !== 0 ||
    (dwFileAttributes & WIN32_ATTR_RECALL_ON_DATA_ACCESS) !== 0 ||
    reparseTag === REPARSE_TAG_CLOUD ||
    reparseTag === REPARSE_TAG_CLOUD_1;

  const isReparsePoint = (dwFileAttributes & WIN32_ATTR_REPARSE_POINT) !== 0;
  if (!isReparsePoint && !isCloudHydrationHazard) {
    return {
      isReparsePoint: false,
      isCloudHydrationHazard: false,
      reparseClassification: null,
    };
  }

  let classification = 'WIN32_REPARSE_UNKNOWN';
  if (reparseTag === REPARSE_TAG_MOUNT_POINT) {
    classification = 'NTFS_JUNCTION_OR_VOLUME_MOUNT';
  } else if (reparseTag === REPARSE_TAG_SYMLINK) {
    classification = 'NTFS_SYMLINK';
  } else if (reparseTag === REPARSE_TAG_WSL) {
    classification = 'NTFS_WSL_SPECIAL_REPARSE';
  } else if (isCloudHydrationHazard) {
    classification = 'ONEDRIVE_OR_CLOUD_RECALL_PLACEHOLDER';
  }

  return {
    isReparsePoint,
    isCloudHydrationHazard,
    reparseClassification: classification,
  };
}

const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;

/**
 * Verifies the raw external 86 manifest bytes against an independently supplied trusted SHA-256
 * digest BEFORE parsing or relying on any manifest rules. Fails closed if missing, malformed,
 * or mismatched. If two independent digests are supplied (e.g., CLI flag + config pin), BOTH
 * must match the computed digest.
 */
export function verifyManifestSha256(
  manifestRawJson: string,
  expectedSha256: string | null | undefined,
  secondaryExpectedSha256?: string | null
): string {
  if (typeof manifestRawJson !== 'string' || manifestRawJson.length === 0) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'EMPTY_MANIFEST_PAYLOAD',
      'External 86 manifest content is empty; failing closed before traversal.'
    );
  }

  const primary = typeof expectedSha256 === 'string' ? expectedSha256.trim().toLowerCase() : '';
  if (!primary) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'MISSING_EXPECTED_MANIFEST_SHA256',
      'An independently trusted expected SHA-256 digest is required to authenticate the external 86 manifest.'
    );
  }
  if (!SHA256_HEX_RE.test(primary)) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'INVALID_EXPECTED_MANIFEST_SHA256_FORMAT',
      'Expected external 86 manifest SHA-256 must be a 64-character hexadecimal string.'
    );
  }

  const computedHex = crypto
    .createHash('sha256')
    .update(manifestRawJson, 'utf8')
    .digest('hex');
  const computedBuf = Buffer.from(computedHex, 'hex');
  const primaryBuf = Buffer.from(primary, 'hex');

  if (!crypto.timingSafeEqual(computedBuf, primaryBuf)) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'MANIFEST_SHA256_MISMATCH',
      'External 86 manifest SHA-256 does not match the independently trusted expected digest; refusing to traverse.'
    );
  }

  if (secondaryExpectedSha256 !== undefined && secondaryExpectedSha256 !== null && secondaryExpectedSha256 !== '') {
    const secondary = secondaryExpectedSha256.trim().toLowerCase();
    if (!SHA256_HEX_RE.test(secondary)) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_86_INIT',
        'INVALID_EXPECTED_MANIFEST_SHA256_FORMAT',
        'Secondary expected external 86 manifest SHA-256 must be a 64-character hexadecimal string.'
      );
    }
    const secondaryBuf = Buffer.from(secondary, 'hex');
    if (!crypto.timingSafeEqual(computedBuf, secondaryBuf)) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_86_INIT',
        'MANIFEST_SHA256_MISMATCH',
        'External 86 manifest SHA-256 disagrees with secondary trusted digest; refusing to traverse.'
      );
    }
  }

  return computedHex;
}

/**
 * Validates Stage 0 Config & External 86 Manifest BEFORE any filesystem traversal.
 * Fails closed immediately on empty roots, invalid paths, Zone A / Zone B overlap,
 * or missing/unverified 86 manifest.
 */
export function validateStage0Preconditions(
  config: Stage0Config,
  manifest: External86Manifest | null | undefined
): {
  normalizedRoots: Array<ScanRootEntry & { canonicalKey: string }>;
  normalizedZoneBKey: string;
} {
  if (!config || config.configVersion !== '1.0.0') {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_CONFIG',
      'UNSUPPORTED_CONFIG_VERSION',
      'Stage 0 config is missing or has an unsupported configVersion.'
    );
  }

  if (
    !Array.isArray(config.scanRootsAllowlist) ||
    config.scanRootsAllowlist.length === 0
  ) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_CONFIG',
      'EMPTY_SCAN_ROOTS_ALLOWLIST',
      'Owner-approved scanRootsAllowlist must contain at least one explicit absolute directory.'
    );
  }

  const manifestPathRes = normalizePathByMode(config.external86ManifestPath, config.hostOsMode);
  if (!manifestPathRes.ok) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      `INVALID_86_MANIFEST_PATH:${manifestPathRes.hazardReason}`,
      `External 86 manifest path failed validation: ${manifestPathRes.hazardReason}`
    );
  }

  if (
    config.expectedExternal86ManifestSha256 !== undefined &&
    !SHA256_HEX_RE.test(config.expectedExternal86ManifestSha256.trim())
  ) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'INVALID_EXPECTED_MANIFEST_SHA256_FORMAT',
      'Configured expectedExternal86ManifestSha256 must be a valid 64-character hex digest.'
    );
  }

  const zoneBRes = normalizePathByMode(config.zoneBOutputDir, config.hostOsMode);
  if (!zoneBRes.ok) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_CONFIG',
      `INVALID_ZONE_B_OUTPUT:${zoneBRes.hazardReason}`,
      `Zone B output path failed validation: ${zoneBRes.hazardReason}`
    );
  }

  if (!manifest || manifest.schemaVersion !== '1.0.0' || !manifest.manifestId) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'MISSING_OR_INVALID_86_MANIFEST',
      'Verified external 86 manifest is required prior to Stage 0 traversal.'
    );
  }

  if (!Array.isArray(manifest.rules)) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'MALFORMED_86_RULES_ARRAY',
      'External 86 manifest rules array is malformed.'
    );
  }

  if (manifest.rules.length === 0 && !manifest.allowEmptyRuleset) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_86_INIT',
      'UNAPPROVED_EMPTY_86_RULESET',
      'External 86 manifest has zero rules without explicit allowEmptyRuleset=true sign-off.'
    );
  }

  if (config.canaryAgentIdentities !== undefined) {
    if (!Array.isArray(config.canaryAgentIdentities)) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_CONFIG',
        'MALFORMED_CANARY_IDENTITIES',
        'canaryAgentIdentities must be an array when specified.'
      );
    }
    const validPrincipalKinds = new Set([
      'INTERACTIVE_OWNER',
      'CLI_AGENT_SAME_UID',
      'ISOLATED_AGENT_UID',
      'SEARCH_SUBPROCESS',
    ]);
    for (const identity of config.canaryAgentIdentities) {
      if (
        !identity ||
        !identity.identityLabel ||
        !validPrincipalKinds.has(identity.principalKind) ||
        (identity.expectedAccess !== 'MUST_DENY' &&
          identity.expectedAccess !== 'DIAGNOSTIC_EXPOSURE_CHECK')
      ) {
        throw new Stage0FailClosedError(
          'FAIL_CLOSED_CONFIG',
          'INVALID_CANARY_IDENTITY_ENTRY',
          'Each canaryAgentIdentities entry must declare identityLabel, principalKind, and expectedAccess.'
        );
      }
    }
  }

  const seenAliases = new Set<string>();
  const normalizedRoots: Array<ScanRootEntry & { canonicalKey: string }> = [];

  for (const root of config.scanRootsAllowlist) {
    if (!/^ROOT_[A-Z0-9_]{1,24}$/.test(root.alias) || seenAliases.has(root.alias)) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_CONFIG',
        'INVALID_OR_DUPLICATE_ROOT_ALIAS',
        `Scan root alias "${root.alias}" must match ROOT_[A-Z0-9_]+ and be unique.`
      );
    }
    seenAliases.add(root.alias);

    const norm = normalizePathByMode(
      root.absolutePath,
      root.expectedFsMode,
      Boolean(root.ntfsCaseSensitiveDir)
    );
    if (!norm.ok) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_CONFIG',
        `INVALID_SCAN_ROOT:${norm.hazardReason}`,
        `Scan root ${root.alias} failed ${root.expectedFsMode} validation: ${norm.hazardReason}`
      );
    }

    // Enforce strict Zone A vs Zone B disjointness
    if (
      root.expectedFsMode === config.hostOsMode &&
      pathsOverlap(norm.canonicalComparisonKey, zoneBRes.canonicalComparisonKey, config.hostOsMode)
    ) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_ZONE_OVERLAP',
        `ZONE_A_OVERLAPS_ZONE_B:${root.alias}`,
        `Zone B output directory overlaps read-only Zone A scan root ${root.alias}.`
      );
    }

    normalizedRoots.push({
      ...root,
      canonicalKey: norm.canonicalComparisonKey,
    });
  }

  // Validate every 86 rule so uncertain rule syntax fails closed upfront
  const validKinds = new Set([
    'PATH_PREFIX',
    'FILENAME_EXACT',
    'GLOB_SEGMENT',
    'POSIX_DEV_INO',
    'NTFS_FILE_ID_128',
    'ARCHIVE_ENTRY_NAME',
    'REVOKED_CONVERSATION_ID',
    'KNOWN_MIXED_CONTAINER',
  ]);
  for (const rule of manifest.rules) {
    if (
      !rule.ruleId ||
      !/^[A-Za-z0-9_-]{2,40}$/.test(rule.ruleId) ||
      !validKinds.has(rule.kind) ||
      !rule.targetValue ||
      !rule.targetValue.trim()
    ) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_86_INIT',
        `UNCERTAIN_86_RULE:${rule?.ruleId ?? 'UNKNOWN'}`,
        `Uncertain or malformed 86 rule in external manifest (${rule?.ruleId ?? 'unnamed'}).`
      );
    }
  }

  return {
    normalizedRoots,
    normalizedZoneBKey: zoneBRes.canonicalComparisonKey,
  };
}

function matchSimpleGlobSegment(segment: string, pattern: string, caseInsensitive: boolean): boolean {
  const s = caseInsensitive ? segment.toLowerCase() : segment;
  const p = caseInsensitive ? pattern.toLowerCase() : pattern;
  const escaped = p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`).test(s);
}

/**
 * Evaluates external metadata BEFORE fs.open() / content reads.
 * Returns matching ruleId or null if cleared.
 */
export function evaluatePreOpen86Rules(params: {
  candidatePath: string;
  entryName: string;
  mode: OsPlatformMode;
  ntfsCaseSensitiveDir?: boolean;
  posixDevIno?: string; // "${dev}:${ino}"
  ntfsFileId128?: string; // "${volSerial}:${fileIdHex}"
  rules: Rule86Entry[];
}): { matched: boolean; ruleId?: string; matchedKind?: Rule86Entry['kind'] } {
  const caseInsensitive = params.mode === 'WINDOWS_NTFS' && !params.ntfsCaseSensitiveDir;
  const normCandidate = normalizePathByMode(
    params.candidatePath,
    params.mode,
    Boolean(params.ntfsCaseSensitiveDir)
  );

  // Fail closed if candidate path cannot be cleanly normalized
  if (!normCandidate.ok) {
    return { matched: true, ruleId: 'FAIL_CLOSED_PATH_HAZARD' };
  }

  const sep = params.mode === 'WINDOWS_NTFS' ? '\\' : '/';
  const entryComp = caseInsensitive ? params.entryName.toLowerCase() : params.entryName;

  for (const rule of params.rules) {
    if (rule.kind === 'PATH_PREFIX' || rule.kind === 'KNOWN_MIXED_CONTAINER') {
      const normRule = normalizePathByMode(
        rule.targetValue,
        params.mode,
        Boolean(params.ntfsCaseSensitiveDir)
      );
      if (!normRule.ok) {
        // Uncertain rule path fails closed!
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
      const targetKey = normRule.canonicalComparisonKey;
      const candKey = normCandidate.canonicalComparisonKey;
      if (candKey === targetKey || candKey.startsWith(targetKey + sep)) {
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
    } else if (rule.kind === 'FILENAME_EXACT') {
      const targetName = caseInsensitive ? rule.targetValue.toLowerCase() : rule.targetValue;
      if (entryComp === targetName) {
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
    } else if (rule.kind === 'GLOB_SEGMENT') {
      if (matchSimpleGlobSegment(params.entryName, rule.targetValue, caseInsensitive)) {
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
    } else if (rule.kind === 'POSIX_DEV_INO' && params.posixDevIno) {
      if (params.posixDevIno === rule.targetValue) {
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
    } else if (rule.kind === 'NTFS_FILE_ID_128' && params.ntfsFileId128) {
      if (params.ntfsFileId128.toLowerCase() === rule.targetValue.toLowerCase()) {
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
    } else if (rule.kind === 'REVOKED_CONVERSATION_ID') {
      const targetId = caseInsensitive ? rule.targetValue.toLowerCase() : rule.targetValue;
      if (
        entryComp.includes(targetId) ||
        normCandidate.canonicalComparisonKey.includes(targetId)
      ) {
        return { matched: true, ruleId: rule.ruleId, matchedKind: rule.kind };
      }
    }
  }

  return { matched: false };
}

export function matchArchiveEntryAgainst86(
  archiveEntryPath: string,
  rules: Rule86Entry[]
): { matched: boolean; ruleId?: string } {
  const normalizedEntry = archiveEntryPath.replace(/\\/g, '/');
  const segments = normalizedEntry.split('/').filter(Boolean);
  const base = path.posix.basename(normalizedEntry);
  for (const rule of rules) {
    if (rule.kind === 'ARCHIVE_ENTRY_NAME' || rule.kind === 'FILENAME_EXACT') {
      const lowerTarget = rule.targetValue.toLowerCase();
      if (
        normalizedEntry.toLowerCase().includes(lowerTarget) ||
        base.toLowerCase() === lowerTarget ||
        segments.some((seg) => seg.toLowerCase() === lowerTarget)
      ) {
        return { matched: true, ruleId: rule.ruleId };
      }
    } else if (rule.kind === 'GLOB_SEGMENT') {
      if (segments.some((seg) => matchSimpleGlobSegment(seg, rule.targetValue, true))) {
        return { matched: true, ruleId: rule.ruleId };
      }
    } else if (rule.kind === 'REVOKED_CONVERSATION_ID') {
      if (normalizedEntry.toLowerCase().includes(rule.targetValue.toLowerCase())) {
        return { matched: true, ruleId: rule.ruleId };
      }
    }
  }
  return { matched: false };
}
