const { Worker } = require('worker_threads')
const os = require('os')
const path = require('path')

class Challenge {
  constructor ({ threads } = {}) {
    const cpus = os.cpus().length
    this.numThreads = Math.max(1, Math.min(threads || Math.max(1, cpus - 2), cpus))
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

      const finish = (share) => {
        if (settled) return
        settled = true
        Atomics.store(cancelArr, 0, 1)
        this._cancel = null
        clearTimeout(safetyTimer)
        for (const { w, handler, errHandler } of listeners) {
          w.removeListener('message', handler)
          w.removeListener('error', errHandler)
        }
        resolve(share)
      }

      const decPending = () => {
        pending--
        if (pending <= 0 && !settled) finish(null)
      }

      const listeners = []

      const safetyTimer = setTimeout(() => {
        if (!settled) finish(null)
      }, timeBudgetMs + 5000)

      for (let i = 0; i < this.numThreads; i++) {
        const w = this.workers[i]
        const id = `${Date.now()}-${Math.random()}-${i}`

        const handler = (msg) => {
          if (msg.id !== id) return
          if (msg.share) {
            finish(msg.share)
          } else {
            decPending()
          }
        }

        const errHandler = () => {
          decPending()
        }

        listeners.push({ w, handler, errHandler })
        w.on('message', handler)
        w.on('error', errHandler)

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
      w.on('error', (err) => console.error('[challenge] worker error:', err))
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
