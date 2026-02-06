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

function meetsTarget(hashHex, targetHex) {
  if (!targetHex || targetHex.length !== 8) return true;
  const hash = Buffer.from(hashHex, 'hex');
  const targetNum = Buffer.from(targetHex, 'hex').readUInt32BE(0);
  const hashNum = Buffer.from(hash.slice(0, 4)).reverse().readUInt32BE(0);
  return hashNum <= targetNum;
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
    const nonceHex = (nonce & 0xFFFFFFFF).toString(16).padStart(8, '0');
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
