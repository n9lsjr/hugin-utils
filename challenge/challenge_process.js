const path = require('path')
const { getNonceOffset } = require('..')

const CHECK_EVERY = 32

let native = null
try {
  native = require('node-gyp-build')(path.join(__dirname, '..'))
} catch {
  try {
    native = require('../build/Release/hugin_helpers.node')
  } catch {
    try {
      native = require('../build/Debug/hugin_helpers.node')
    } catch {}
  }
}

let hashSync = null
try {
  const cryptoDir = path.dirname(require.resolve('kryptokrona-crypto'))
  const addonPaths = [
    path.join(cryptoDir, '..', 'build', 'Release', 'turtlecoin-crypto.node'),
    path.join(cryptoDir, '..', 'build', 'Debug', 'turtlecoin-crypto.node'),
    path.join(cryptoDir, 'build', 'Release', 'turtlecoin-crypto.node')
  ]
  let binding = null
  for (const p of addonPaths) {
    try { binding = require(p); break } catch {}
  }
  if (binding && typeof binding.cn_turtle_lite_slow_hash_v2 === 'function') {
    hashSync = (hex) => {
      const [err, hash] = binding.cn_turtle_lite_slow_hash_v2(hex.toLowerCase())
      if (err) return null
      return hash
    }
  }
} catch {}

let hashAsync = null
if (!hashSync) {
  const { Crypto } = require('kryptokrona-utils')
  const crypto = new Crypto()
  hashAsync = (hex) => crypto.cn_turtle_lite_slow_hash_v2(hex)
}

const U64 = 0xFFFFFFFFFFFFFFFFn
const U32 = 0xFFFFFFFFn

function parseTarget (hex) {
  if (typeof hex !== 'string' || hex.length !== 8) return null
  let raw = 0
  for (let i = 0; i < 4; i++) {
    const b = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    if (!Number.isFinite(b)) return null
    raw |= b << (i * 8)
  }
  raw = raw >>> 0
  if (raw === 0) return null
  const denom = U32 / BigInt(raw)
  if (denom === 0n) return null
  return U64 / denom
}

function nonceToHexLE (n) {
  n = n >>> 0
  return (
    (n & 0xff).toString(16).padStart(2, '0') +
    ((n >>> 8) & 0xff).toString(16).padStart(2, '0') +
    ((n >>> 16) & 0xff).toString(16).padStart(2, '0') +
    ((n >>> 24) & 0xff).toString(16).padStart(2, '0')
  )
}

function meetsTarget (hashHex, target) {
  if (hashHex.length < 64) return false
  let lo = 0; let hi = 0
  for (let i = 0; i < 4; i++) {
    lo |= parseInt(hashHex.slice(48 + i * 2, 50 + i * 2), 16) << (i * 8)
    hi |= parseInt(hashHex.slice(56 + i * 2, 58 + i * 2), 16) << (i * 8)
  }
  const tail = (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0)
  return tail <= target
}

let cancelled = false

function solveSync (blob, targetHex, jobId, startNonce, timeBudgetMs) {
  const offset = getNonceOffset(blob)
  const deadline = Date.now() + timeBudgetMs
  let nonce = startNonce >>> 0

  const c = offset * 2
  const prefix = blob.slice(0, c)
  const suffix = blob.slice(c + 8)

  const target = native ? null : parseTarget(targetHex)
  if (!native && target === null) return null

  let iter = 0
  while (true) {
    if ((iter & (CHECK_EVERY - 1)) === 0) {
      if (cancelled) return null
      if (Date.now() >= deadline) return null
    }
    iter++

    const blobHex = native
      ? native.insertNonce(prefix, suffix, nonce)
      : prefix + nonceToHexLE(nonce) + suffix

    const result = hashSync(blobHex)

    const found = native
      ? native.checkHash(result, targetHex)
      : meetsTarget(result, target)

    if (found) {
      return {
        job_id: jobId,
        nonce: native ? native.nonceToHexLE(nonce) : nonceToHexLE(nonce),
        result: result.toLowerCase()
      }
    }
    nonce = (nonce + 1) >>> 0
  }
}

async function solveAsync (blob, targetHex, jobId, startNonce, timeBudgetMs) {
  const offset = getNonceOffset(blob)
  const deadline = Date.now() + timeBudgetMs
  let nonce = startNonce >>> 0

  const c = offset * 2
  const prefix = blob.slice(0, c)
  const suffix = blob.slice(c + 8)

  const target = native ? null : parseTarget(targetHex)
  if (!native && target === null) return null

  let iter = 0
  while (true) {
    if ((iter & (CHECK_EVERY - 1)) === 0) {
      if (cancelled) return null
      if (Date.now() >= deadline) return null
    }
    iter++

    const blobHex = native
      ? native.insertNonce(prefix, suffix, nonce)
      : prefix + nonceToHexLE(nonce) + suffix

    const result = await hashAsync(blobHex)

    const found = native
      ? native.checkHash(result, targetHex)
      : meetsTarget(result, target)

    if (found) {
      return {
        job_id: jobId,
        nonce: native ? native.nonceToHexLE(nonce) : nonceToHexLE(nonce),
        result: result.toLowerCase()
      }
    }
    nonce = (nonce + 1) >>> 0
  }
}

process.on('message', async (msg) => {
  if (msg.type === 'cancel') {
    cancelled = true
    return
  }
  if (msg.type !== 'solve') return
  cancelled = false
  try {
    const share = hashSync
      ? solveSync(msg.blob, msg.target, msg.jobId, msg.startNonce, msg.timeBudgetMs)
      : await solveAsync(msg.blob, msg.target, msg.jobId, msg.startNonce, msg.timeBudgetMs)
    process.send({ id: msg.id, share })
  } catch (err) {
    process.send({ id: msg.id, share: null, error: String(err) })
  }
})
