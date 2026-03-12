const path = require('path')
const { fork } = require('child_process')
const os = require('os')

const DEFAULT_THREADS = 4

function resolve_thread_count(explicit) {
  const envThreads = parseInt(process.env.HUGIN_POW_THREADS || '', 10)
  const wanted = Number.isFinite(explicit) && explicit > 0
    ? Math.floor(explicit)
    : (Number.isFinite(envThreads) && envThreads > 0 ? Math.floor(envThreads) : DEFAULT_THREADS)
  const cpuCount = Math.max(1, (os.cpus() || []).length || 1)
  return Math.max(1, Math.min(wanted, cpuCount))
}

function nonce_ranges(count) {
  const step = Math.floor(0xFFFFFFFF / Math.max(1, count))
  return Array.from({ length: count }, (_, i) => (step * i) >>> 0)
}

function create_node_worker_backend({
  max_job_time_ms = 90000,
  threads
} = {}) {
  const NUM_THREADS = resolve_thread_count(threads)
  const NONCE_RANGES = nonce_ranges(NUM_THREADS)
  const workers = []
  let workers_ready = false
  const requests = new Map()
  let cleanup_set = false

  function ensure_workers() {
    if (workers.length > 0 && workers_ready) return
    const worker_path = path.join(__dirname, '..', 'node_worker_process.cjs')
    for (let i = 0; i < NUM_THREADS; i++) {
      const w = fork(worker_path, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] })
      workers.push(w)

      w.on('message', (msg) => {
        if (!msg || !msg.req_id) return
        const pending = requests.get(msg.req_id)
        if (!pending) return
        requests.delete(msg.req_id)
        if (msg.type === 'result') {
          pending.resolve(msg.result)
          return
        }
        const error = msg.error || 'pow_worker_error'
        pending.reject(new Error(error))
      })

      w.on('exit', () => {
        if (!workers_ready) return
        workers_ready = false
        for (const w2 of workers) {
          try { w2.kill() } catch (e) {}
        }
        workers.length = 0
        const err = new Error('pow_worker_exit')
        for (const [, p] of requests) p.reject(err)
        requests.clear()
      })
    }
    workers_ready = true

    if (!cleanup_set) {
      cleanup_set = true
      const cleanup = () => {
        for (const w of workers) {
          try { w.kill() } catch (e) {}
        }
        workers.length = 0
        workers_ready = false
      }
      process.once('exit', cleanup)
      process.once('SIGINT', cleanup)
      process.once('SIGTERM', cleanup)
      process.once('beforeExit', cleanup)
    }
  }

  function call_worker(type, payload, timeout_ms, thread_index = 0) {
    ensure_workers()
    const req_id = `${Date.now()}-${Math.random()}-${thread_index}`
    const promise = new Promise((resolve, reject) => {
      let timer = null
      if (timeout_ms && timeout_ms > 0) {
        const backlog = requests.size
        const per_req_slack = Math.min(timeout_ms, 5000)
        const effective_timeout_ms = timeout_ms + (backlog * per_req_slack) + 500
        timer = setTimeout(() => {
          if (requests.has(req_id)) {
            requests.delete(req_id)
            reject(new Error('pow_worker_timeout'))
          }
        }, effective_timeout_ms)
      }
      requests.set(req_id, {
        timer,
        resolve: (result) => {
          if (timer) clearTimeout(timer)
          resolve(result)
        },
        reject: (error) => {
          if (timer) clearTimeout(timer)
          reject(error)
        },
        thread_index
      })
      workers[thread_index].send({ type, req_id, payload })
    })
    return { req_id, promise }
  }

  function abort_request(req_id) {
    const pending = requests.get(req_id)
    if (!pending) return
    if (pending.timer) clearTimeout(pending.timer)
    requests.delete(req_id)
  }

  function cancel_worker_request(thread_index, req_id) {
    if (!workers[thread_index]) return
    try {
      workers[thread_index].send({ type: 'cancel_share', req_id })
    } catch (e) {}
  }

  return {
    async find_share({ job, hashes_per_second, time_budget_ms }) {
      const tms = parseInt(time_budget_ms, 10)
      const timeout_ms = tms > 0 ? tms + 1500 : max_job_time_ms + 1500
      const base = Math.floor(Math.random() * 0xFFFFFFFF)
      const opts = {
        hashes_per_second: parseInt(hashes_per_second, 10),
        time_budget_ms: tms,
        max_job_time_ms
      }

      const workerCalls = []
      for (let i = 0; i < NUM_THREADS; i++) {
        const start_nonce = (base + NONCE_RANGES[i]) >>> 0
        workerCalls.push(
          call_worker('find_share', { job, start_nonce, options: opts }, timeout_ms, i)
        )
      }

      const race = workerCalls.map(({ promise }) =>
        promise.then((share) => {
          if (share) return share
          throw new Error('pow_no_share')
        })
      )

      try {
        const winner = await Promise.any(race)
        for (let i = 0; i < workerCalls.length; i++) {
          const id = workerCalls[i].req_id
          if (!id) continue
          abort_request(id)
          cancel_worker_request(i, id)
        }
        return winner
      } catch (e) {
        return null
      }
    }
  }
}

module.exports = { create_node_worker_backend }

