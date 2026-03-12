const { Crypto } = require('kryptokrona-utils')
const { getNonceOffset } = require('..')

const crypto = new Crypto()
const active = new Map()

const U64 = 0xFFFFFFFFFFFFFFFFn
const U32 = 0xFFFFFFFFn

function readUInt32LEFromHex(hex, byteOffset) {
  const pos = byteOffset * 2
  const b0 = parseInt(hex.slice(pos, pos + 2), 16)
  const b1 = parseInt(hex.slice(pos + 2, pos + 4), 16)
  const b2 = parseInt(hex.slice(pos + 4, pos + 6), 16)
  const b3 = parseInt(hex.slice(pos + 6, pos + 8), 16)
  if (![b0, b1, b2, b3].every(Number.isFinite)) return null
  return ((b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0)
}

function parseTarget(targetHex) {
  if (typeof targetHex !== 'string') return null
  if (targetHex.length === 8) {
    const raw = readUInt32LEFromHex(targetHex, 0)
    if (!raw) return null
    const denom = U32 / BigInt(raw)
    if (denom === 0n) return null
    return U64 / denom
  }
  if (targetHex.length === 16) {
    const lo = readUInt32LEFromHex(targetHex, 0)
    const hi = readUInt32LEFromHex(targetHex, 4)
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) return null
    return (BigInt(hi) << 32n) | BigInt(lo)
  }
  return null
}

function hashTailToU64(hashHex) {
  if (typeof hashHex !== 'string' || hashHex.length < 64) return null
  const lo = readUInt32LEFromHex(hashHex, 24)
  const hi = readUInt32LEFromHex(hashHex, 28)
  if (!Number.isFinite(lo) || !Number.isFinite(hi)) return null
  return (BigInt(hi) << 32n) | BigInt(lo)
}

function nonceToHexLE(nonce) {
  const n = nonce >>> 0
  const b0 = (n & 0xff).toString(16).padStart(2, '0')
  const b1 = ((n >>> 8) & 0xff).toString(16).padStart(2, '0')
  const b2 = ((n >>> 16) & 0xff).toString(16).padStart(2, '0')
  const b3 = ((n >>> 24) & 0xff).toString(16).padStart(2, '0')
  return `${b0}${b1}${b2}${b3}`
}

async function pow_find_share(job, start_nonce, options = {}, req_id) {
  if (!job || typeof job.blob !== 'string' || typeof job.target !== 'string') return null

  const hashes_per_second = Math.max(1, parseInt(options.hashes_per_second, 10) || 1)
  const time_budget_ms = Math.max(1, parseInt(options.time_budget_ms, 10) || 1)
  const max_job_time_ms = Math.max(0, parseInt(options.max_job_time_ms, 10) || 0)
  const max_attempts = Math.max(1, Math.floor((hashes_per_second * time_budget_ms) / 1000))

  const target = parseTarget(job.target)
  if (target === null) return null

  let nonce = start_nonce >>> 0
  const start = Date.now()

  const nonceOffsetBytes = getNonceOffset(job.blob)
  const nonceOffsetChars = nonceOffsetBytes * 2
  if (!Number.isFinite(nonceOffsetChars) || nonceOffsetChars < 0 || (nonceOffsetChars + 8) > job.blob.length) return null

  const blobPrefix = job.blob.slice(0, nonceOffsetChars)
  const blobSuffix = job.blob.slice(nonceOffsetChars + 8)

  for (let attempt = 0; attempt < max_attempts; attempt++) {
    const state = active.get(req_id)
    if (!state || state.cancelled) return null

    const elapsed = Date.now() - start
    if (elapsed >= time_budget_ms) return null
    if (max_job_time_ms > 0 && elapsed >= max_job_time_ms) return null

    const nonceHex = nonceToHexLE(nonce)
    const blobHex = `${blobPrefix}${nonceHex}${blobSuffix}`
    const result = crypto.cn_turtle_lite_slow_hash_v2(blobHex)
    const hashTail = hashTailToU64(result)
    if (hashTail !== null && hashTail <= target) {
      return { job_id: job.job_id, nonce: nonceHex, result: result.toLowerCase() }
    }

    nonce = (nonce + 1) >>> 0

    // Yield occasionally so cancellation messages can be processed quickly.
    if ((attempt & 0x7f) === 0) {
      await new Promise((resolve) => setImmediate(resolve))
    }
  }

  return null
}

async function pow_calculate_shares(job, required_shares = 1, options = {}, req_id) {
  if (!job || !job.blob || !job.target) {
    throw new Error('Invalid job data')
  }
  const shares = []
  let nonce = Math.floor(Math.random() * 0xFFFFFFFF)
  const start = Date.now()
  const max_job_time_ms = parseInt(options.max_job_time_ms, 10)
  for (let i = 0; i < required_shares; i++) {
    if (max_job_time_ms > 0 && (Date.now() - start) >= max_job_time_ms) break
    const share = await pow_find_share(job, nonce, options, req_id)
    if (share) {
      shares.push(share)
      nonce = parseInt(share.nonce, 16) + 1
    }
  }
  return { job, shares }
}

process.on('message', async (msg) => {
  if (!msg || !msg.type || !msg.req_id) return
  const { type, req_id, payload } = msg
  if (type === 'cancel_share') {
    const state = active.get(req_id)
    if (state) state.cancelled = true
    return
  }
  try {
    if (type === 'find_share') {
      const { job, start_nonce, options } = payload || {}
      active.set(req_id, { cancelled: false })
      const result = await pow_find_share(job, start_nonce, options || {}, req_id)
      active.delete(req_id)
      process.send && process.send({ type: 'result', req_id, result })
      return
    }
    if (type === 'calculate_shares') {
      const { job, required_shares, options } = payload || {}
      active.set(req_id, { cancelled: false })
      const result = await pow_calculate_shares(job, required_shares, options || {}, req_id)
      active.delete(req_id)
      process.send && process.send({ type: 'result', req_id, result })
      return
    }
    process.send && process.send({ type: 'error', req_id, error: 'unknown_request' })
  } catch (e) {
    active.delete(req_id)
    process.send && process.send({ type: 'error', req_id, error: e && e.message })
  }
})

