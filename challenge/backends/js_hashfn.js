const { findShare } = require('../..')

function create_js_hashfn_backend({ hash_fn }) {
  if (typeof hash_fn !== 'function') throw new Error('hash_fn_missing')

  return {
    async find_share({ job, hashes_per_second, time_budget_ms, nonce_tag_bits, nonce_tag_value }) {
      return await findShare({
        job,
        startNonce: Math.floor(Math.random() * 0xFFFFFFFF),
        hashesPerSecond: parseInt(hashes_per_second, 10),
        timeBudgetMs: parseInt(time_budget_ms, 10),
        nonceTagBits: nonce_tag_bits,
        nonceTagValue: nonce_tag_value,
        hashFn: async (blobHex) => await hash_fn(blobHex)
      })
    }
  }
}

module.exports = { create_js_hashfn_backend }

