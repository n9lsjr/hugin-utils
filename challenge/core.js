const { nonceTagFromMessageHash, extractPrevIdFromBlob } = require('..')

class ChallengeScheduler {
  constructor() {
    this.active = 0
  }
  acquire() {
    this.active++
    let released = false
    return () => {
      if (released) return
      released = true
      this.active = Math.max(0, this.active - 1)
    }
  }
  active_count() {
    return this.active
  }
}

function create_pow_scheduler() {
  return new ChallengeScheduler()
}

function create_rate_policy({
  total_hashes_per_second_cap = 1500,
  phase1_hashes_per_second_cap = 950,
  phase2_hashes_per_second_cap = 250,
  phase1_ms = 2 * 60 * 1000,
  slice_ms_phase1 = 10000,
  slice_ms_phase2 = 10000
} = {}) {
  return ({ active_tasks, elapsed_ms }) => {
    const in_phase1 = elapsed_ms < phase1_ms
    const per_task_budget = Math.max(1, Math.floor(total_hashes_per_second_cap / Math.max(1, active_tasks)))
    const hashes_per_second = Math.min(
      per_task_budget,
      in_phase1 ? phase1_hashes_per_second_cap : phase2_hashes_per_second_cap
    )
    const time_budget_ms = in_phase1 ? slice_ms_phase1 : slice_ms_phase2
    return { hashes_per_second, time_budget_ms, in_phase1 }
  }
}

function create_freshness_policy({ get_current_prev_ids }) {
  return (job) => {
    if (!job || !job.blob) return false
    const prevId = extractPrevIdFromBlob(job.blob)
    const { currentPrevId, previousPrevId } = get_current_prev_ids()
    if (!prevId || !currentPrevId) return false
    return prevId === currentPrevId || prevId === previousPrevId
  }
}

async function message_challenge({
  get_job,
  backend,
  message_hash,
  required_shares = 1,
  nonce_tag_bits = 4,
  scheduler,
  rate_policy,
  freshness_policy,
  log
}) {
  if (!backend || typeof backend.find_share !== 'function') throw new Error('pow_backend_missing')
  if (typeof get_job !== 'function') throw new Error('pow_get_job_missing')
  if (!scheduler) scheduler = create_pow_scheduler()
  if (!rate_policy) rate_policy = create_rate_policy()

  const release = scheduler.acquire()
  try {
    const start = Date.now()
    const nonce_tag_value = nonceTagFromMessageHash(message_hash, nonce_tag_bits)

    const shares = []
    const share_nonces = new Set()
    const push_share = (share) => {
      if (!share) return
      if (typeof share.nonce !== 'string' || typeof share.result !== 'string') return
      const nonce = share.nonce.toLowerCase()
      if (share_nonces.has(nonce)) return
      share_nonces.add(nonce)
      shares.push({ ...share, job_id: String(share.job_id), nonce, result: share.result.toLowerCase() })
    }

    let did_boost = false
    while (shares.length < required_shares) {
      const job = await get_job()
      if (!job) {
        await new Promise(r => setTimeout(r, 250))
        continue
      }

      if (freshness_policy && !freshness_policy(job)) {
        if (log) log('pow_stale_local', { jobId: job.job_id })
        await new Promise(r => setTimeout(r, 250))
        continue
      }

      const elapsed_ms = Date.now() - start
      const active_tasks = scheduler.active_count()
      const { hashes_per_second, time_budget_ms, in_phase1 } = rate_policy({ active_tasks, elapsed_ms })

      // Optional early boost pass.
      if (in_phase1 && !did_boost && backend.boost_find_share) {
        did_boost = true
        try {
          const share = await backend.boost_find_share({
            job,
            hashes_per_second,
            time_budget_ms: Math.min(4000, time_budget_ms),
            nonce_tag_bits,
            nonce_tag_value,
            log
          })
          if (share) push_share(share)
          if (shares.length >= required_shares) return { job, shares }
        } catch (e) {}
      }

      let share = null
      try {
        share = await backend.find_share({
          job,
          hashes_per_second,
          time_budget_ms,
          nonce_tag_bits,
          nonce_tag_value,
          log
        })
      } catch (e) {
        if (e && e.message === 'pow_worker_timeout') {
          if (log) log('pow_worker_timeout_retry', { jobId: job.job_id, sliceMs: time_budget_ms, hps: hashes_per_second })
          await new Promise(r => setTimeout(r, in_phase1 ? 100 : 300))
          continue
        }
        throw e
      }

      if (share) {
        push_share(share)
        if (shares.length >= required_shares) return { job, shares }
      }

      await new Promise(r => setTimeout(r, in_phase1 ? 50 : 250))
    }
    return null
  } finally {
    release()
  }
}

module.exports = {
  create_pow_scheduler,
  create_rate_policy,
  create_freshness_policy,
  message_challenge
}

