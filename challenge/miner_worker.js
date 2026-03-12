const { parentPort } = require('worker_threads')
const { getNonceOffset } = require('..')
const { Crypto } = require('kryptokrona-utils')

const crypto = new Crypto()

let native = null
try {
  native = require('../build/Release/hugin_helpers.node')
} catch {
  try {
    native = require('../build/Debug/hugin_helpers.node')
  } catch {}
}

// ── JS helpers (used when native addon not built) ──

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

// ── Mining loop ──

function mine (blob, targetHex, jobId, startNonce, timeBudgetMs, cancel, cancelIndex) {
  const offset = getNonceOffset(blob)
  const cancelArr = new Int32Array(cancel)
  const start = Date.now()
  let nonce = startNonce >>> 0

  if (native) {
    const c = offset * 2
    const prefix = blob.slice(0, c)
    const suffix = blob.slice(c + 8)

    while (true) {
      if (Atomics.load(cancelArr, cancelIndex) !== 0) return null
      if (Date.now() - start >= timeBudgetMs) return null

      const blobHex = native.insertNonce(prefix, suffix, nonce)
      const result = crypto.cn_turtle_lite_slow_hash_v2(blobHex)

      if (native.checkHash(result, targetHex)) {
        return {
          job_id: jobId,
          nonce: native.nonceToHexLE(nonce),
          result: result.toLowerCase()
        }
      }
      nonce = (nonce + 1) >>> 0
    }
  }

  // JS fallback
  const target = parseTarget(targetHex)
  if (target === null) return null

  const c = offset * 2
  const prefix = blob.slice(0, c)
  const suffix = blob.slice(c + 8)

  while (true) {
    if (Atomics.load(cancelArr, cancelIndex) !== 0) return null
    if (Date.now() - start >= timeBudgetMs) return null

    const nonceHex = nonceToHexLE(nonce)
    const blobHex = prefix + nonceHex + suffix
    const result = crypto.cn_turtle_lite_slow_hash_v2(blobHex)

    if (meetsTarget(result, target)) {
      return { job_id: jobId, nonce: nonceHex, result: result.toLowerCase() }
    }
    nonce = (nonce + 1) >>> 0
  }
}

parentPort.on('message', (msg) => {
  if (msg.type !== 'mine') return
  const share = mine(
    msg.blob, msg.target, msg.jobId,
    msg.startNonce, msg.timeBudgetMs,
    msg.cancel, msg.cancelIndex
  )
  parentPort.postMessage({ id: msg.id, share })
})
