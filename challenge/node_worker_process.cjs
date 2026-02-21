const { Crypto } = require('kryptokrona-utils')
const { findShare, nonceMatchesTag } = require('..')

const crypto = new Crypto()

function logPow(event, data) {
  process.send && process.send({ type: 'log', event, data })
}

async function pow_find_share(job, start_nonce, options = {}) {
  const hashes_per_second = parseInt(options.hashes_per_second, 10)
  const time_budget_ms = parseInt(options.time_budget_ms, 10)
  const max_job_time_ms = parseInt(options.max_job_time_ms, 10)
  const nonceTagBits = parseInt(options.nonceTagBits || '0', 10)
  const nonceTagValue = parseInt(options.nonceTagValue || '0', 10)
  const tag_enabled = Number.isFinite(nonceTagBits) && nonceTagBits > 0

  let nonce = start_nonce >>> 0
  const start = Date.now()
  while (true) {
    const elapsed = Date.now() - start
    const remaining_ms = time_budget_ms - elapsed
    if (remaining_ms <= 0) return null
    if (max_job_time_ms > 0 && elapsed >= max_job_time_ms) return null

    const slice_ms = Math.min(1000, remaining_ms)
    const share = await findShare({
      job,
      startNonce: nonce,
      hashesPerSecond: hashes_per_second,
      timeBudgetMs: slice_ms,
      nonceTagBits,
      nonceTagValue,
      hashFn: (blobHex) => crypto.cn_turtle_lite_slow_hash_v2(blobHex),
      log: (event, data) => logPow(event, data)
    })

    if (share) {
      const nextNonce = (parseInt(share.nonce, 16) + 1) >>> 0
      if (!tag_enabled || nonceMatchesTag(share.nonce, nonceTagValue, nonceTagBits)) {
        return share
      }
      nonce = nextNonce
      continue
    }

    const slice_attempts = Math.max(1, Math.floor(hashes_per_second * (slice_ms / 1000)))
    nonce = (nonce + slice_attempts) >>> 0
  }
}

async function pow_calculate_shares(job, required_shares = 1, options = {}) {
  if (!job || !job.blob || !job.target) {
    throw new Error('Invalid job data')
  }
  const shares = []
  let nonce = Math.floor(Math.random() * 0xFFFFFFFF)
  const start = Date.now()
  const max_job_time_ms = parseInt(options.max_job_time_ms, 10)
  for (let i = 0; i < required_shares; i++) {
    if (max_job_time_ms > 0 && (Date.now() - start) >= max_job_time_ms) break
    const share = await pow_find_share(job, nonce, options)
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
  try {
    if (type === 'find_share') {
      const { job, start_nonce, options } = payload || {}
      const result = await pow_find_share(job, start_nonce, options || {})
      process.send && process.send({ type: 'result', req_id, result })
      return
    }
    if (type === 'calculate_shares') {
      const { job, required_shares, options } = payload || {}
      const result = await pow_calculate_shares(job, required_shares, options || {})
      process.send && process.send({ type: 'result', req_id, result })
      return
    }
    process.send && process.send({ type: 'error', req_id, error: 'unknown_request' })
  } catch (e) {
    process.send && process.send({ type: 'error', req_id, error: e && e.message })
  }
})

