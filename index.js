const DEFAULT_NONCE_OFFSET = 39;
const { Crypto } = require('kryptokrona-utils')
const crypto = new Crypto()

function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex_to_bytes_invalid')
  if (hex.length % 2 !== 0) throw new Error('hex_to_bytes_len')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, (i * 2) + 2), 16)
    if (!Number.isFinite(byte)) throw new Error('hex_to_bytes_parse')
    out[i] = byte
  }
  return out
}

function bytesToHex(bytes) {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

function readUInt32LE(bytes, offset) {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>> 0
  )
}

function readBigUInt64LE(bytes, offset) {
  const lo = BigInt(readUInt32LE(bytes, offset))
  const hi = BigInt(readUInt32LE(bytes, offset + 4))
  return (hi << 32n) | lo
}

function readVarint(buffer, offset) {
  let value = 0;
  let shift = 0;
  let bytes = 0;
  while (offset + bytes < buffer.length) {
    const byte = buffer[offset + bytes];
    value |= (byte & 0x7f) << shift;
    bytes += 1;
    if ((byte & 0x80) === 0) {
      return { value, bytes };
    }
    shift += 7;
    if (shift > 63) return null;
  }
  return null;
}

function getNonceOffsetFromBuffer(blobBuffer) {
  try {
    let offset = 0;
    const major = readVarint(blobBuffer, offset);
    if (!major) return DEFAULT_NONCE_OFFSET;
    offset += major.bytes;
    const minor = readVarint(blobBuffer, offset);
    if (!minor) return DEFAULT_NONCE_OFFSET;
    offset += minor.bytes;
    const timestamp = readVarint(blobBuffer, offset);
    if (!timestamp) return DEFAULT_NONCE_OFFSET;
    offset += timestamp.bytes;
    offset += 32;
    return offset;
  } catch (e) {
    return DEFAULT_NONCE_OFFSET;
  }
}

function getNonceOffset(blobHex) {
  const blobBuffer = hexToBytes(blobHex);
  return getNonceOffsetFromBuffer(blobBuffer);
}

function insertNonce(blobHex, nonceHex) {
  const blobBuffer = hexToBytes(blobHex);
  const nonceBuffer = hexToBytes(nonceHex);
  const offset = getNonceOffsetFromBuffer(blobBuffer);
  blobBuffer.set(nonceBuffer, offset);
  return { blobHex: bytesToHex(blobBuffer), offset };
}

function extractPrevIdFromBlob(blobHex) {
  try {
    const blobBuffer = hexToBytes(blobHex);
    let offset = 0;
    const major = readVarint(blobBuffer, offset);
    if (!major) return null;
    offset += major.bytes;
    const minor = readVarint(blobBuffer, offset);
    if (!minor) return null;
    offset += minor.bytes;
    const timestamp = readVarint(blobBuffer, offset);
    if (!timestamp) return null;
    offset += timestamp.bytes;
    if (offset + 32 > blobBuffer.length) return null;
    return bytesToHex(blobBuffer.subarray(offset, offset + 32));
  } catch (e) {
    return null;
  }
}

function nonceToHexLE(nonce) {
  const n = nonce >>> 0
  const out = new Uint8Array(4)
  out[0] = n & 0xff
  out[1] = (n >>> 8) & 0xff
  out[2] = (n >>> 16) & 0xff
  out[3] = (n >>> 24) & 0xff
  return bytesToHex(out)
}

function parseTarget(targetHex) {
  if (!targetHex) return null;
  const targetBytes = hexToBytes(targetHex)
  if (targetBytes.length === 4) {
    const raw = readUInt32LE(targetBytes, 0);
    if (raw === 0) return null;
    const numerator = 0xFFFFFFFFFFFFFFFFn;
    const denom = 0xFFFFFFFFn / BigInt(raw);
    if (denom === 0n) return null;
    return numerator / denom;
  }
  if (targetBytes.length === 8) {
    return readBigUInt64LE(targetBytes, 0);
  }
  return null;
}

function meetsTarget(hashHex, targetHex) {
  const target = parseTarget(targetHex);
  if (target === null) return true;
  const hashBytes = hexToBytes(hashHex);
  if (hashBytes.length < 32) return false;
  const hashTail = readBigUInt64LE(hashBytes, 24);
  return hashTail <= target;
}

function isHexString(value) {
  return typeof value === 'string' && /^[0-9a-f]+$/i.test(value)
}

function isValidPowJob(job) {
  if (!job || typeof job !== 'object') return false
  if (typeof job.job_id !== 'string' || job.job_id.length > 32) return false
  if (typeof job.blob !== 'string' || !isHexString(job.blob) || job.blob.length % 2 !== 0) return false
  if (typeof job.target !== 'string' || !isHexString(job.target) || job.target.length !== 8) return false
  return true
}

async function verifyShare(job, nonce, result) {
  if (!isValidPowJob(job)) return false
  if (typeof nonce !== 'string' || nonce.length !== 8 || !isHexString(nonce)) return false
  if (typeof result !== 'string' || result.length !== 64 || !isHexString(result)) return false
  const { blobHex } = insertNonce(job.blob, nonce)
  const hashHex = await crypto.cn_turtle_lite_slow_hash_v2(blobHex)
  if (hashHex !== result) return false
  return meetsTarget(hashHex, job.target)
}

function checkHash(hashHex, targetHex) {
  return meetsTarget(hashHex, targetHex)
}

function minTargetHex(a, b) {
  const aa = parseTarget(a);
  const bb = parseTarget(b);
  if (aa === null) return b;
  if (bb === null) return a;
  return aa <= bb ? a : b;
}

function toHex(str) {
  let result = ''
  for (let i = 0; i < str.length; i++) {
    result += str.charCodeAt(i).toString(16)
  }
  return result
}

function firstDigestByteFromHex(hex) {
  if (typeof hex !== 'string' || hex.length < 2) throw new Error('cn_fast_hash_invalid_hex')
  const value = parseInt(hex.slice(0, 2), 16)
  if (!Number.isFinite(value)) throw new Error('cn_fast_hash_parse_failed')
  return value
}

function nonceTagFromMessageHash(messageHash, bits) {
  try {
    const b = typeof bits === 'number' ? bits : 0;
    if (b <= 0 || b > 16) return 0;
    const mask = (1 << b) - 1;
    const input = String(messageHash);
    const digestHex = crypto.cn_fast_hash(toHex(input))
    const digest0 = firstDigestByteFromHex(digestHex)
    return digest0 & mask
  } catch (e) {
    return 0;
  }
}

function nonceMatchesTag(nonceHex, tagValue, bits) {
  if (typeof nonceHex !== 'string' || nonceHex.length !== 8) return false;
  const b = typeof bits === 'number' ? bits : 0;
  if (b <= 0) return true;
  const mask = (1 << b) - 1;
  // Tag is computed over the actual 32-bit nonce value inserted into the blob (little-endian).
  const nonceBytes = hexToBytes(nonceHex)
  const nonce = readUInt32LE(nonceBytes, 0)
  return (nonce & mask) === (tagValue & mask);
}

async function findShare({
  job,
  startNonce,
  hashFn,
  log,
  hashesPerSecond = 500,
  timeBudgetMs = 1000,
  yieldEvery = 200,
  logEvery = 100,
  nonceTagBits = 0,
  nonceTagValue = 0
}) {
  const maxAttempts = Math.max(1, Math.floor((hashesPerSecond * timeBudgetMs) / 1000));
  let nonce = startNonce;
  const start = Date.now();
  const b = typeof nonceTagBits === 'number' ? nonceTagBits : 0;
  const mask = b > 0 ? ((1 << b) - 1) : 0;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (b > 0 && ((nonce >>> 0) & mask) !== (nonceTagValue & mask)) {
      nonce++;
      continue;
    }
    const nonceHex = nonceToHexLE(nonce);
    const { blobHex, offset } = insertNonce(job.blob, nonceHex);
    if (log) log('nonce_offset', { jobId: job.job_id, offset });
    const result = await hashFn(blobHex);

    if (meetsTarget(result, job.target)) {
      if (log) log('pow_share_found', { jobId: job.job_id, nonce: nonceHex, attempt });
      return { job_id: job.job_id, nonce: nonceHex, result };
    }

    nonce++;
    if (attempt > 0 && attempt % logEvery === 0) {
      if (log) log('pow_progress', { jobId: job.job_id, attempt, nonce: nonceHex });
    }
    if (attempt > 0 && attempt % yieldEvery === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    if (Date.now() - start >= timeBudgetMs) {
      if (log) log('pow_time_budget', { jobId: job.job_id, attempt, elapsedMs: Date.now() - start });
      break;
    }
  }

  if (log) log('pow_share_exhausted', { jobId: job.job_id, attempts: maxAttempts });
  return null;
}

module.exports = {
  readVarint,
  getNonceOffset,
  insertNonce,
  meetsTarget,
  checkHash,
  minTargetHex,
  extractPrevIdFromBlob,
  isHexString,
  isValidPowJob,
  verifyShare,
  nonceTagFromMessageHash,
  nonceMatchesTag,
  findShare,
  hexToBytes,
  bytesToHex
};
