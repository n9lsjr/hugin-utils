const { Worker } = require('worker_threads')
const os = require('os')
const path = require('path')

class Challenge {
  constructor ({ threads } = {}) {
    const cpus = os.cpus().length
    this.numThreads = Math.max(1, Math.min(threads || cpus, cpus))
    this.workers = []
    this.currentJob = null
    this._cancel = null
  }

  setJob (job) {
    if (!job || !job.job_id || !job.blob || !job.target) return
    if (this.currentJob && this.currentJob.job_id === job.job_id) return
    this.currentJob = job
    if (this._cancel) Atomics.store(this._cancel, 0, 1)
  }

  hasJob () {
    return !!this.currentJob
  }

  async findShare (timeBudgetMs = 30000) {
    if (!this.currentJob) return null
    this._ensureWorkers()

    const cancel = new SharedArrayBuffer(4)
    const cancelArr = new Int32Array(cancel)
    this._cancel = cancelArr

    const job = this.currentJob
    const step = Math.floor(0xFFFFFFFF / this.numThreads)
    const base = (Math.random() * 0xFFFFFFFF) >>> 0

    return new Promise((resolve) => {
      let settled = false
      let pending = this.numThreads

      for (let i = 0; i < this.numThreads; i++) {
        const w = this.workers[i]
        const id = `${Date.now()}-${Math.random()}-${i}`

        const handler = (msg) => {
          if (msg.id !== id) return
          w.removeListener('message', handler)
          pending--

          if (msg.share && !settled) {
            settled = true
            Atomics.store(cancelArr, 0, 1)
            this._cancel = null
            resolve(msg.share)
          } else if (pending === 0 && !settled) {
            this._cancel = null
            resolve(null)
          }
        }

        w.on('message', handler)
        w.postMessage({
          type: 'mine',
          id,
          blob: job.blob,
          target: job.target,
          jobId: job.job_id,
          startNonce: (base + step * i) >>> 0,
          timeBudgetMs,
          cancel,
          cancelIndex: 0
        })
      }
    })
  }

  _ensureWorkers () {
    if (this.workers.length >= this.numThreads) return
    const workerPath = path.join(__dirname, 'miner_worker.js')
    for (let i = this.workers.length; i < this.numThreads; i++) {
      const w = new Worker(workerPath)
      w.on('error', (err) => console.error('[miner] worker error:', err))
      this.workers.push(w)
    }
  }

  destroy () {
    if (this._cancel) Atomics.store(this._cancel, 0, 1)
    for (const w of this.workers) {
      try { w.terminate() } catch {}
    }
    this.workers = []
    this._cancel = null
  }
}

function createChallenge (opts) {
  return new Challenge(opts)
}

module.exports = { createChallenge, Challenge }
