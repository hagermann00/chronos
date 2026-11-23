import fs from 'node:fs';

export type SqliteQuarantineReason =
  | 'SQLITE_HEADER_INVALID'
  | 'SQLITE_WAL_MODE_HEADER'
  | 'SQLITE_WAL_SIDECAR_PRESENT'
  | 'SQLITE_SHM_SIDECAR_PRESENT'
  | 'SQLITE_HOT_JOURNAL_PRESENT'
  | 'SQLITE_OPEN_OR_READ_ERROR';

export interface SqliteHeaderAndSidecarCheck {
  safeForImmutableDdlInspection: boolean;
  quarantineReason?: SqliteQuarantineReason;
  writeVersion?: number;
  readVersion?: number;
  detectedSidecars: string[];
}

const SQLITE_HEADER_MAGIC = Buffer.from('SQLite format 3\0', 'ascii');
const SQLITE_HEADER_LENGTH = 100;
const SQLITE_SIDECAR_SUFFIXES = ['-wal', '-shm', '-journal'] as const;

export function detectSqliteSidecarsNoFollow(sqlitePath: string): string[] {
  const detected: string[] = [];

  for (const suffix of SQLITE_SIDECAR_SUFFIXES) {
    const sidecarPath = `${sqlitePath}${suffix}`;
    try {
      fs.lstatSync(sidecarPath);
      detected.push(suffix);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === 'ENOENT') {
        continue;
      }
      // Fail closed on unexpected errors (e.g., EACCES, EPERM, EIO, ENOTDIR).
      detected.push(suffix);
    }
  }

  return detected;
}

export function inspectSqliteHeaderBytes(headerBuf: Buffer): {
  valid: boolean;
  writeVersion?: number;
  readVersion?: number;
  quarantineReason?: SqliteQuarantineReason;
} {
  if (
    headerBuf.length < SQLITE_HEADER_LENGTH ||
    !headerBuf.subarray(0, 16).equals(SQLITE_HEADER_MAGIC)
  ) {
    return {
      valid: false,
      quarantineReason: 'SQLITE_HEADER_INVALID',
    };
  }

  const writeVersion = headerBuf[18];
  const readVersion = headerBuf[19];

  if (writeVersion === 2 || readVersion === 2) {
    return {
      valid: false,
      writeVersion,
      readVersion,
      quarantineReason: 'SQLITE_WAL_MODE_HEADER',
    };
  }

  if (writeVersion !== 1 || readVersion !== 1) {
    return {
      valid: false,
      writeVersion,
      readVersion,
      quarantineReason: 'SQLITE_HEADER_INVALID',
    };
  }

  return {
    valid: true,
    writeVersion,
    readVersion,
  };
}

export function checkSqliteSafeForImmutableInspection(
  fd: number,
  sqlitePath: string
): SqliteHeaderAndSidecarCheck {
  const detectedSidecars = detectSqliteSidecarsNoFollow(sqlitePath);

  if (detectedSidecars.includes('-wal')) {
    return {
      safeForImmutableDdlInspection: false,
      quarantineReason: 'SQLITE_WAL_SIDECAR_PRESENT',
      detectedSidecars,
    };
  }

  if (detectedSidecars.includes('-shm')) {
    return {
      safeForImmutableDdlInspection: false,
      quarantineReason: 'SQLITE_SHM_SIDECAR_PRESENT',
      detectedSidecars,
    };
  }

  if (detectedSidecars.includes('-journal')) {
    return {
      safeForImmutableDdlInspection: false,
      quarantineReason: 'SQLITE_HOT_JOURNAL_PRESENT',
      detectedSidecars,
    };
  }

  const headerBuf = Buffer.alloc(SQLITE_HEADER_LENGTH);
  let bytesRead = 0;
  try {
    bytesRead = fs.readSync(fd, headerBuf, 0, SQLITE_HEADER_LENGTH, 0);
  } catch {
    return {
      safeForImmutableDdlInspection: false,
      quarantineReason: 'SQLITE_OPEN_OR_READ_ERROR',
      detectedSidecars,
    };
  }

  if (bytesRead < SQLITE_HEADER_LENGTH) {
    return {
      safeForImmutableDdlInspection: false,
      quarantineReason: 'SQLITE_OPEN_OR_READ_ERROR',
      detectedSidecars,
    };
  }

  const hdr = inspectSqliteHeaderBytes(headerBuf);
  if (!hdr.valid) {
    return {
      safeForImmutableDdlInspection: false,
      quarantineReason: hdr.quarantineReason,
      writeVersion: hdr.writeVersion,
      readVersion: hdr.readVersion,
      detectedSidecars,
    };
  }

  return {
    safeForImmutableDdlInspection: true,
    writeVersion: hdr.writeVersion,
    readVersion: hdr.readVersion,
    detectedSidecars: [],
  };
}
