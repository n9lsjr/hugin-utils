function create_native_batch_backend({ native_find_share }) {
  if (typeof native_find_share !== 'function') throw new Error('native_find_share_missing')

  return {
    async find_share({ job, hashes_per_second, time_budget_ms, nonce_tag_bits, nonce_tag_value }) {
      const res = await native_find_share(
        job.blob,
        job.target,
        0,
        time_budget_ms,
        nonce_tag_bits,
        nonce_tag_value
      )
      if (!res) return null
      return {
        job_id: job.job_id,
        nonce: res.nonceHex || res.nonce || res.nonce_hex,
        result: res.resultHex || res.result || res.result_hex
      }
    }
  }
}

module.exports = { create_native_batch_backend }

