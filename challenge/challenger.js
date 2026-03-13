const { fork } = require('child_process')
const os = require('os')
const path = require('path')

class Challenge {
  constructor ({ threads } = {}) {
    const cpus = os.cpus().length
    this.numThreads = Math.max(1, Math.min(threads || Math.max(1, cpus - 2), cpus))
    this.procs = []
    this.currentJob = null
    this._cancelled = false
  }

  setJob (job) {
    if (!job || !job.job_id || !job.blob || !job.target) return
    if (this.currentJob && this.currentJob.job_id === job.job_id) return
    this.currentJob = job
    this._cancel()
  }

  hasJob () {
    return !!this.currentJob
  }

  async findShare (timeBudgetMs = 30000) {
    if (!this.currentJob) return null
    this._ensureProcs()

    this._cancelled = false
    const job = this.currentJob
    const step = Math.floor(0xFFFFFFFF / this.numThreads)
    const base = (Math.random() * 0xFFFFFFFF) >>> 0

    return new Promise((resolve) => {
      let settled = false
      let pending = this.numThreads

      const finish = (share) => {
        if (settled) return
        settled = true
        this._cancel()
        clearTimeout(safetyTimer)
        for (const { proc, handler, errHandler } of listeners) {
          proc.removeListener('message', handler)
          proc.removeListener('error', errHandler)
          proc.removeListener('exit', errHandler)
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
        const proc = this.procs[i]
        if (!proc || !proc.connected) {
          decPending()
          continue
        }

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

        listeners.push({ proc, handler, errHandler })
        proc.on('message', handler)
        proc.on('error', errHandler)
        proc.on('exit', errHandler)

        proc.send({
          type: 'solve',
          id,
          blob: job.blob,
          target: job.target,
          jobId: job.job_id,
          startNonce: (base + step * i) >>> 0,
          timeBudgetMs
        })
      }
    })
  }

  _cancel () {
    this._cancelled = true
    for (const proc of this.procs) {
      try {
        if (proc.connected) proc.send({ type: 'cancel' })
      } catch {}
    }
  }

  _ensureProcs () {
    const alive = this.procs.filter(p => p && p.connected)
    if (alive.length >= this.numThreads) return
    this.procs = alive
    const scriptPath = path.join(__dirname, 'challenge_process.js')
    for (let i = this.procs.length; i < this.numThreads; i++) {
      const proc = fork(scriptPath, [], { stdio: 'ignore' })
      proc.on('error', (err) => console.error('[challenge] process error:', err))
      proc.on('exit', () => {
        const idx = this.procs.indexOf(proc)
        if (idx !== -1) this.procs[idx] = null
      })
      this.procs.push(proc)
    }
  }

  destroy () {
    this._cancel()
    for (const proc of this.procs) {
      try {
        if (proc && proc.connected) proc.kill()
      } catch {}
    }
    this.procs = []
    this._cancelled = false
  }
}

function createChallenge (opts) {
  return new Challenge(opts)
}

module.exports = { createChallenge, Challenge }
