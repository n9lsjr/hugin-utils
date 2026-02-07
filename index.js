const DEFAULT_NONCE_OFFSET = 39;

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
  const blobBuffer = Buffer.from(blobHex, 'hex');
  return getNonceOffsetFromBuffer(blobBuffer);
}

function insertNonce(blobHex, nonceHex) {
  const blobBuffer = Buffer.from(blobHex, 'hex');
  const nonceBuffer = Buffer.from(nonceHex, 'hex');
  const offset = getNonceOffsetFromBuffer(blobBuffer);
  nonceBuffer.copy(blobBuffer, offset);
  return { blobHex: blobBuffer.toString('hex'), offset };
}

function nonceToHexLE(nonce) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(nonce >>> 0, 0);
  return buf.toString('hex');
}

function parseTarget(targetHex) {
  if (!targetHex) return null;
  const targetBuffer = Buffer.from(targetHex, 'hex');
  if (targetBuffer.length === 4) {
    const raw = targetBuffer.readUInt32LE(0);
    if (raw === 0) return null;
    const numerator = 0xFFFFFFFFFFFFFFFFn;
    const denom = 0xFFFFFFFFn / BigInt(raw);
    if (denom === 0n) return null;
    return numerator / denom;
  }
  if (targetBuffer.length === 8) {
    return targetBuffer.readBigUInt64LE(0);
  }
  return null;
}

function meetsTarget(hashHex, targetHex) {
  const target = parseTarget(targetHex);
  if (target === null) return true;
  const hash = Buffer.from(hashHex, 'hex');
  if (hash.length < 32) return false;
  const hashTail = hash.readBigUInt64LE(24);
  return hashTail <= target;
}

async function findShare({
  job,
  startNonce,
  hashFn,
  log,
  hashesPerSecond = 500,
  timeBudgetMs = 1000,
  yieldEvery = 200,
  logEvery = 100
}) {
  const maxAttempts = Math.max(1, Math.floor((hashesPerSecond * timeBudgetMs) / 1000));
  let nonce = startNonce;
  const start = Date.now();

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
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
  findShare
};
