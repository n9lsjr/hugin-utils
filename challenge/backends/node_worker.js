const path = require('path')
const { fork } = require('child_process')

function create_node_worker_backend({
  max_job_time_ms = 90000
} = {}) {
  let worker = null
  let worker_ready = false
  const requests = new Map()
  let cleanup_set = false

  function ensure_worker() {
    if (worker && worker_ready) return
    const worker_path = path.join(__dirname, '..', 'node_worker_process.cjs')
    worker = fork(worker_path, [], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] })
    worker_ready = true

    if (!cleanup_set) {
      cleanup_set = true
      const cleanup = () => {
        if (worker) {
          try { worker.kill() } catch (e) {}
          worker = null
          worker_ready = false
        }
      }
      process.once('exit', cleanup)
      process.once('SIGINT', cleanup)
      process.once('SIGTERM', cleanup)
      process.once('beforeExit', cleanup)
    }

    worker.on('message', (msg) => {
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

    worker.on('exit', (code) => {
      worker_ready = false
      for (const [, pending] of requests) {
        pending.reject(new Error(`pow_worker_exit_${code}`))
      }
      requests.clear()
    })
  }

  function call_worker(type, payload, timeout_ms) {
    ensure_worker()
    return new Promise((resolve, reject) => {
      const req_id = `${Date.now()}-${Math.random()}`
      let timer = null
      if (timeout_ms && timeout_ms > 0) {
        const backlog = requests.size
        const per_req_slack = Math.min(timeout_ms, 5000)
        const effective_timeout_ms = timeout_ms + (backlog * per_req_slack) + 500
        timer = setTimeout(() => {
          requests.delete(req_id)
          reject(new Error('pow_worker_timeout'))
        }, effective_timeout_ms)
      }
      requests.set(req_id, {
        resolve: (result) => {
          if (timer) clearTimeout(timer)
          resolve(result)
        },
        reject: (error) => {
          if (timer) clearTimeout(timer)
          reject(error)
        }
      })
      worker.send({ type, req_id, payload })
    })
  }

  return {
    async find_share({ job, hashes_per_second, time_budget_ms, nonce_tag_bits, nonce_tag_value }) {
      const tms = parseInt(time_budget_ms, 10)
      const timeout_ms = tms > 0 ? tms + 1500 : max_job_time_ms + 1500
      return await call_worker('find_share', {
        job,
        start_nonce: Math.floor(Math.random() * 0xFFFFFFFF),
        options: {
          hashes_per_second: parseInt(hashes_per_second, 10),
          time_budget_ms: tms,
          max_job_time_ms,
          nonceTagBits: nonce_tag_bits,
          nonceTagValue: nonce_tag_value
        }
      }, timeout_ms)
    }
  }
}

module.exports = { create_node_worker_backend }

