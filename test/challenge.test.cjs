const assert = require('assert')

const {
  getNonceOffset,
  insertNonce,
  meetsTarget,
  nonceTagFromMessageHash,
  nonceMatchesTag,
  findShare
} = require('..')

async function test_insert_nonce_defaults() {
  const blobHex = '00'.repeat(100)
  const nonceHex = '01020304'
  const { blobHex: outHex, offset } = insertNonce(blobHex, nonceHex)
  assert.strictEqual(offset, getNonceOffset(blobHex))
  assert.strictEqual(offset, 39)
  const inserted = outHex.slice(offset * 2, (offset * 2) + 8)
  assert.strictEqual(inserted, nonceHex)
}

function test_meets_target_64bit() {
  const targetHex = '0000000000000000' // 0
  const okHash = '00'.repeat(32)
  const badHash = '00'.repeat(24) + '0100000000000000' // tail=1 (LE)
  assert.strictEqual(meetsTarget(okHash, targetHex), true)
  assert.strictEqual(meetsTarget(badHash, targetHex), false)
}

async function test_nonce_tag_roundtrip() {
  const bits = 4
  const messageHash = 'test-message-hash'
  const tagValue = nonceTagFromMessageHash(messageHash, bits)

  const job = {
    job_id: '1',
    blob: '00'.repeat(100),
    target: 'ffffffff'
  }

  const share = await findShare({
    job,
    startNonce: 0,
    nonceTagBits: bits,
    nonceTagValue: tagValue,
    hashesPerSecond: 10_000,
    timeBudgetMs: 50,
    hashFn: async () => '00'.repeat(32)
  })

  assert.ok(share, 'expected share')
  assert.strictEqual(share.job_id, job.job_id)
  assert.ok(nonceMatchesTag(share.nonce, tagValue, bits), 'share nonce must match nonce-tag')
}

async function run() {
  await test_insert_nonce_defaults()
  test_meets_target_64bit()
  await test_nonce_tag_roundtrip()
  console.log('ok')
}

run().catch((e) => {
  console.error(e)
  process.exit(1)
})

