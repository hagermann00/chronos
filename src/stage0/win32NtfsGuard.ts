import { execFileSync } from 'node:child_process';
import path from 'node:path';
import {
  classifyWin32AttributesAndReparse,
  evaluatePreOpen86Rules,
  normalizeWindowsNtfsPath,
  pathsOverlap,
} from './pathSecurity.ts';
import type { Rule86Entry } from './types.ts';

export interface Win32NtfsEntryMetadata {
  available: boolean;
  fileAttributes: number;
  reparseTag?: number;
  nNumberOfLinks: number;
  volumeSerialHex: string;
  fileIdHex: string;
  ntfsFileId128: string;
  finalPath: string;
  isDirectory: boolean;
  isReparsePoint: boolean;
  isCloudHydrationHazard: boolean;
  reparseClassification: string | null;
  errorCode?: string;
}

export type Win32SafeCheckResult =
  | { ok: true; meta: Win32NtfsEntryMetadata }
  | {
      ok: false;
      reason:
        | 'REPARSE_OR_SYMLINK'
        | 'CLOUD_PLACEHOLDER'
        | 'HARDLINK'
        | 'REVOKED_NTFS_FILE_ID'
        | 'PATH_ESCAPE_OR_86'
        | 'WIN32_NATIVE_VERIFICATION_UNAVAILABLE';
      matchedRuleId?: string;
      meta?: Win32NtfsEntryMetadata;
    };

interface RawPsInspectPayload {
  ok: boolean;
  errorCode?: string;
  fileAttributes?: number;
  reparseTag?: number | null;
  nNumberOfLinks?: number;
  volumeSerialHex?: string;
  fileIdHex?: string;
  finalPath?: string;
  isDirectory?: boolean;
}

const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

const WIN32_INSPECT_PS_SCRIPT = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$targetPath = $env:CHRONOS_WIN32_TARGET_PATH
if ([string]::IsNullOrEmpty($targetPath)) {
  [ordered]@{ ok = $false; errorCode = 'EMPTY_TARGET_PATH' } | ConvertTo-Json -Compress
  exit 0
}
$csCode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ChronosStage0 {
  public static class NtfsNativeGuard {
    private const uint FILE_READ_ATTRIBUTES = 0x00000080;
    private const uint FILE_SHARE_ALL = 0x00000007;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const int FileAttributeTagInfo = 9;
    private const int FileIdInfo = 18;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME {
      public uint dwLowDateTime;
      public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION {
      public uint dwFileAttributes;
      public FILETIME ftCreationTime;
      public FILETIME ftLastAccessTime;
      public FILETIME ftLastWriteTime;
      public uint dwVolumeSerialNumber;
      public uint nFileSizeHigh;
      public uint nFileSizeLow;
      public uint nNumberOfLinks;
      public uint nFileIndexHigh;
      public uint nFileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_ATTRIBUTE_TAG_INFO {
      public uint FileAttributes;
      public uint ReparseTag;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
      string lpFileName,
      uint dwDesiredAccess,
      uint dwShareMode,
      IntPtr lpSecurityAttributes,
      uint dwCreationDisposition,
      uint dwFlagsAndAttributes,
      IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
      SafeFileHandle hFile,
      out BY_HANDLE_FILE_INFORMATION lpFileInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
      SafeFileHandle hFile,
      int fileInformationClass,
      out FILE_ATTRIBUTE_TAG_INFO lpFileInformation,
      uint dwBufferSize
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
      SafeFileHandle hFile,
      int fileInformationClass,
      IntPtr lpFileInformation,
      uint dwBufferSize
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
      SafeFileHandle hFile,
      StringBuilder lpszFilePath,
      uint cchFilePath,
      uint dwFlags
    );

    private static string BytesToLowerHex(byte[] bytes) {
      char[] chars = new char[bytes.Length * 2];
      const string hex = "0123456789abcdef";
      for (int i = 0; i < bytes.Length; i++) {
        byte b = bytes[i];
        chars[i * 2] = hex[(b >> 4) & 0x0F];
        chars[i * 2 + 1] = hex[b & 0x0F];
      }
      return new string(chars);
    }

    public static object Inspect(string path) {
      using (SafeFileHandle handle = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_ALL,
        IntPtr.Zero,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        IntPtr.Zero
      )) {
        if (handle.IsInvalid) {
          int err = Marshal.GetLastWin32Error();
          return new { ok = false, errorCode = "WIN32_CREATEFILE_ERR_" + err };
        }

        BY_HANDLE_FILE_INFORMATION basicInfo;
        if (!GetFileInformationByHandle(handle, out basicInfo)) {
          int err = Marshal.GetLastWin32Error();
          return new { ok = false, errorCode = "WIN32_GETFILEINFO_ERR_" + err };
        }

        uint attrs = basicInfo.dwFileAttributes;
        bool isDir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        bool isReparse = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        Nullable<uint> reparseTag = null;
        if (isReparse) {
          FILE_ATTRIBUTE_TAG_INFO tagInfo;
          if (GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            out tagInfo,
            (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))
          )) {
            reparseTag = tagInfo.ReparseTag;
          }
        }

        string volSerialHex;
        string fileIdHex;
        IntPtr fileIdBuf = Marshal.AllocHGlobal(24);
        try {
          if (GetFileInformationByHandleEx(handle, FileIdInfo, fileIdBuf, 24u)) {
            ulong vol64 = (ulong)Marshal.ReadInt64(fileIdBuf, 0);
            byte[] id128 = new byte[16];
            Marshal.Copy(new IntPtr(fileIdBuf.ToInt64() + 8), id128, 0, 16);
            volSerialHex = vol64.ToString("x16");
            fileIdHex = BytesToLowerHex(id128);
          } else {
            ulong index64 = (((ulong)basicInfo.nFileIndexHigh) << 32) | basicInfo.nFileIndexLow;
            volSerialHex = basicInfo.dwVolumeSerialNumber.ToString("x8");
            fileIdHex = index64.ToString("x16");
          }
        } finally {
          Marshal.FreeHGlobal(fileIdBuf);
        }

        StringBuilder pathBuf = new StringBuilder(1024);
        uint pathLen = GetFinalPathNameByHandleW(handle, pathBuf, (uint)pathBuf.Capacity, 0u);
        if (pathLen >= pathBuf.Capacity) {
          pathBuf = new StringBuilder((int)pathLen + 1);
          pathLen = GetFinalPathNameByHandleW(handle, pathBuf, (uint)pathBuf.Capacity, 0u);
        }

        string finalPath = string.Empty;
        if (pathLen > 0 && pathLen < pathBuf.Capacity) {
          finalPath = pathBuf.ToString(0, (int)pathLen);
        } else if (!isReparse) {
          int err = Marshal.GetLastWin32Error();
          return new { ok = false, errorCode = "WIN32_FINALPATH_ERR_" + err };
        }

        return new {
          ok = true,
          fileAttributes = attrs,
          reparseTag = reparseTag,
          nNumberOfLinks = basicInfo.nNumberOfLinks,
          volumeSerialHex = volSerialHex,
          fileIdHex = fileIdHex,
          finalPath = finalPath,
          isDirectory = isDir
        };
      }
    }
  }
}
'@
if (-not ([System.Management.Automation.PSTypeName]'ChronosStage0.NtfsNativeGuard').Type) {
  Add-Type -TypeDefinition $csCode -Language CSharp
}
$res = [ChronosStage0.NtfsNativeGuard]::Inspect($targetPath)
$res | ConvertTo-Json -Compress -Depth 4
`;

function unavailableMetadata(errorCode: string): Win32NtfsEntryMetadata {
  return {
    available: false,
    fileAttributes: 0,
    nNumberOfLinks: 0,
    volumeSerialHex: '',
    fileIdHex: '',
    ntfsFileId128: '',
    finalPath: '',
    isDirectory: false,
    isReparsePoint: false,
    isCloudHydrationHazard: false,
    reparseClassification: null,
    errorCode,
  };
}

/**
 * Inspects a Win32 NTFS path via CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
 * without following symlinks/junctions, extracting attributes, reparse tag, hardlink count,
 * 128-bit NTFS File ID, and canonical final handle path.
 * Fails closed (available: false) on non-win32 hosts or any native/subprocess error.
 */
export function inspectWin32NtfsHandleNoFollow(
  targetPath: string,
  timeoutMs = 4000
): Win32NtfsEntryMetadata {
  if (process.platform !== 'win32') {
    return unavailableMetadata('NOT_WIN32_HOST');
  }
  if (!targetPath || typeof targetPath !== 'string' || targetPath.includes('\0')) {
    return unavailableMetadata('INVALID_WIN32_TARGET_PATH');
  }

  let stdout = '';
  try {
    stdout = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', WIN32_INSPECT_PS_SCRIPT],
      {
        encoding: 'utf8',
        timeout: timeoutMs,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          CHRONOS_WIN32_TARGET_PATH: targetPath,
        },
      }
    );
  } catch (err: unknown) {
    const errObj = err as { code?: string; killed?: boolean; signal?: string } | undefined;
    if (errObj?.code === 'ETIMEDOUT' || errObj?.killed) {
      return unavailableMetadata('WIN32_POWERSHELL_TIMEOUT');
    }
    return unavailableMetadata(
      errObj?.code ? `WIN32_POWERSHELL_ERR_${errObj.code}` : 'WIN32_POWERSHELL_EXEC_FAILED'
    );
  }

  let parsed: RawPsInspectPayload;
  try {
    parsed = JSON.parse(stdout.trim()) as RawPsInspectPayload;
  } catch {
    return unavailableMetadata('WIN32_JSON_PARSE_FAILED');
  }

  if (!parsed || !parsed.ok) {
    return unavailableMetadata(parsed?.errorCode || 'WIN32_NATIVE_INSPECT_FAILED');
  }

  const fileAttributes =
    typeof parsed.fileAttributes === 'number' ? parsed.fileAttributes : 0;
  const reparseTag =
    typeof parsed.reparseTag === 'number' ? parsed.reparseTag : undefined;
  const nNumberOfLinks =
    typeof parsed.nNumberOfLinks === 'number' ? parsed.nNumberOfLinks : 0;
  const volumeSerialHex =
    typeof parsed.volumeSerialHex === 'string' ? parsed.volumeSerialHex : '';
  const fileIdHex = typeof parsed.fileIdHex === 'string' ? parsed.fileIdHex : '';
  const ntfsFileId128 =
    volumeSerialHex && fileIdHex ? `${volumeSerialHex}:${fileIdHex}` : '';
  const finalPath = typeof parsed.finalPath === 'string' ? parsed.finalPath : '';
  const isDirectory =
    typeof parsed.isDirectory === 'boolean'
      ? parsed.isDirectory
      : (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) !== 0;

  const classified = classifyWin32AttributesAndReparse(fileAttributes, reparseTag);
  const isReparsePoint =
    classified.isReparsePoint || (fileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) !== 0;

  return {
    available: true,
    fileAttributes,
    ...(reparseTag !== undefined ? { reparseTag } : {}),
    nNumberOfLinks,
    volumeSerialHex,
    fileIdHex,
    ntfsFileId128,
    finalPath,
    isDirectory,
    isReparsePoint,
    isCloudHydrationHazard: classified.isCloudHydrationHazard,
    reparseClassification: classified.reparseClassification,
  };
}

/**
 * Verifies a Win32 NTFS entry without following reparse points/symlinks.
 * Enforces fail-closed checks on native availability, cloud hydration placeholders,
 * reparse points, pre-open 86 rules (including 128-bit NTFS File ID revocation),
 * non-directory hardlink aliases, and canonical root containment.
 */
export function verifyWin32NtfsEntryNoFollow(params: {
  targetPath: string;
  rootCanonicalKey: string;
  ntfsCaseSensitiveDir?: boolean;
  rules: Rule86Entry[];
  metadataOverride?: Win32NtfsEntryMetadata;
  expectDirectory?: boolean;
}): Win32SafeCheckResult {
  const meta =
    params.metadataOverride ?? inspectWin32NtfsHandleNoFollow(params.targetPath);

  if (!meta.available) {
    return {
      ok: false,
      reason: 'WIN32_NATIVE_VERIFICATION_UNAVAILABLE',
      meta,
    };
  }

  if (meta.isCloudHydrationHazard) {
    return {
      ok: false,
      reason: 'CLOUD_PLACEHOLDER',
      meta,
    };
  }

  if (meta.isReparsePoint) {
    return {
      ok: false,
      reason: 'REPARSE_OR_SYMLINK',
      meta,
    };
  }

  const candidateForRule = meta.finalPath || params.targetPath;
  const hit = evaluatePreOpen86Rules({
    candidatePath: candidateForRule,
    entryName: path.win32.basename(candidateForRule),
    mode: 'WINDOWS_NTFS',
    ntfsCaseSensitiveDir: params.ntfsCaseSensitiveDir,
    ntfsFileId128: meta.ntfsFileId128,
    rules: params.rules,
  });

  if (hit.matched) {
    if (hit.matchedKind === 'NTFS_FILE_ID_128') {
      return {
        ok: false,
        reason: 'REVOKED_NTFS_FILE_ID',
        matchedRuleId: hit.ruleId,
        meta,
      };
    }
    return {
      ok: false,
      reason: 'PATH_ESCAPE_OR_86',
      matchedRuleId: hit.ruleId,
      meta,
    };
  }

  if (!meta.isDirectory && meta.nNumberOfLinks > 1) {
    return {
      ok: false,
      reason: 'HARDLINK',
      meta,
    };
  }

  const normFinal = normalizeWindowsNtfsPath(
    meta.finalPath,
    Boolean(params.ntfsCaseSensitiveDir)
  );
  const rootKey =
    params.rootCanonicalKey.length > 3 && params.rootCanonicalKey.endsWith('\\')
      ? params.rootCanonicalKey.slice(0, -1)
      : params.rootCanonicalKey;
  const rootPrefix = rootKey.endsWith('\\') ? rootKey : `${rootKey}\\`;
  const withinRoot =
    normFinal.ok &&
    (normFinal.canonicalComparisonKey === rootKey ||
      normFinal.canonicalComparisonKey.startsWith(rootPrefix)) &&
    (rootKey.length <= 3 ||
      pathsOverlap(normFinal.canonicalComparisonKey, rootKey, 'WINDOWS_NTFS'));

  if (!withinRoot) {
    return {
      ok: false,
      reason: 'PATH_ESCAPE_OR_86',
      meta,
    };
  }

  return { ok: true, meta };
}

/**
 * Builds an immutable, read-only SQLite URI (`?mode=ro&immutable=1`) for safe
 * Stage 0 inspection without creating WAL/SHM sidecars or mutating source ledgers.
 */
export function buildSqliteReadOnlyImmutableUri(
  sqlitePath: string,
  linuxFd?: number
): string {
  if (typeof linuxFd === 'number') {
    if (!Number.isInteger(linuxFd) || linuxFd < 0) {
      throw new Error(`Invalid Linux file descriptor for SQLite URI: ${linuxFd}`);
    }
    return `file:/proc/self/fd/${linuxFd}?mode=ro&immutable=1`;
  }

  if (!sqlitePath || typeof sqlitePath !== 'string' || sqlitePath.includes('\0')) {
    throw new Error('SQLite path must be a non-empty string without NUL bytes.');
  }

  let working = sqlitePath;
  if (working.startsWith('\\\\?\\')) {
    working = working.slice(4);
  }

  const forward = working.replace(/\\/g, '/');
  const winDriveMatch = /^([A-Za-z]):(?:\/(.*))?$/.exec(forward);
  if (winDriveMatch) {
    const drive = winDriveMatch[1];
    const rest = winDriveMatch[2] ?? '';
    const encodedSegments = rest
      .split('/')
      .filter((seg) => seg.length > 0)
      .map((seg) => encodeURIComponent(seg))
      .join('/');
    return `file:///${drive}:/${encodedSegments}?mode=ro&immutable=1`;
  }

  if (!forward.startsWith('/')) {
    throw new Error(`SQLite path must be absolute: ${sqlitePath}`);
  }

  const encodedSegments = forward
    .split('/')
    .filter((seg) => seg.length > 0)
    .map((seg) => encodeURIComponent(seg))
    .join('/');
  return `file:///${encodedSegments}?mode=ro&immutable=1`;
}
