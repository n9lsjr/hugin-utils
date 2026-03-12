# hugin-utils

PoW utils for hugin node messages.

## Usage

```js
const { insertNonce, meetsTarget, findShare } = require('hugin-utils');
```

## Reusable challenge engine (desktop + mobile)

### Engine API

```js
const {
  message_challenge,
  create_pow_scheduler,
  create_rate_policy
} = require('hugin-utils/challenge')
```

`message_challenge({ get_job, backend, message_hash, required_shares, nonce_tag_bits, scheduler, rate_policy, freshness_policy, log })`

- `get_job() -> Promise<job|null>`: provide the latest pool job `{ job_id, blob, target }`
- `backend.find_share(...) -> Promise<share|null>`: platform-specific PoW backend
- `scheduler`: shared instance to enforce total H/s budget across concurrent message sends
- `rate_policy({ active_tasks, elapsed_ms }) -> { hashes_per_second, time_budget_ms, in_phase1 }`
- `freshness_policy(job) -> boolean`: optional prevId freshness check

### Desktop backend (Node worker)

```js
const { create_node_worker_backend } = require('hugin-utils/challenge/node_worker')
const backend = create_node_worker_backend()
```

Note: the Node-worker backend uses `kryptokrona-utils` (which uses native `kryptokrona-crypto`) for `cn_turtle_lite_slow_hash_v2`.

Tuning:

- Default worker count is `4` (capped to CPU count).
- Override with `create_node_worker_backend({ threads: N })` or `HUGIN_POW_THREADS=N`.
- For the node-worker backend, nonce-tag filtering parameters are ignored for max throughput.

### Mobile backend (native batch scan)

You selected a native batch-scan interface. Implement a native function with the shape:

- `native_find_share(jobBlobHex, targetHex, startNonce, timeBudgetMs, tagBits, tagValue) -> { nonceHex, resultHex } | null`

Then wrap it:

```js
const { create_native_batch_backend } = require('hugin-utils/challenge')
const backend = create_native_batch_backend({ native_find_share })
```

#### React Native example

Example using `NativeModules` (you can adapt this to TurboModules/JSI).

```js
import { NativeModules } from 'react-native'
import {
  message_challenge,
  create_pow_scheduler,
  create_rate_policy,
  create_native_batch_backend
} from 'hugin-utils/challenge'

// Your native module must expose:
// findShare(jobBlobHex, targetHex, startNonce, timeBudgetMs, tagBits, tagValue)
const { HuginPow } = NativeModules

const backend = create_native_batch_backend({
  native_find_share: async (jobBlobHex, targetHex, startNonce, timeBudgetMs, tagBits, tagValue) => {
    const res = await HuginPow.findShare(jobBlobHex, targetHex, startNonce, timeBudgetMs, tagBits, tagValue)
    // Expect { nonceHex, resultHex } or null
    return res
  }
})

// Share across concurrent sends to enforce total H/s cap.
const scheduler = create_pow_scheduler()
const rate_policy = create_rate_policy({
  total_hashes_per_second_cap: 1500,
  phase1_hashes_per_second_cap: 950,
  phase2_hashes_per_second_cap: 250
})

export async function challenge_message({ get_job, message_hash }) {
  return await message_challenge({
    get_job,          // () => Promise<{ job_id, blob, target }|null>
    backend,
    message_hash,     // string (the message id/hash you tag the nonce with)
    required_shares: 1,
    nonce_tag_bits: 4,
    scheduler,
    rate_policy
  })
}
```

#### Mobile (easiest) when you only have `cn_pico` hash()

If your native side only exposes a single function like `cn_pico(blobHex) -> hashHex`, you can keep the nonce search loop in JS and just provide the hash function:

```js
import { NativeModules } from 'react-native'
import {
  message_challenge,
  create_pow_scheduler,
  create_rate_policy,
  create_js_hashfn_backend
} from 'hugin-utils/challenge'

const { HuginPow } = NativeModules

const backend = create_js_hashfn_backend({
  // Must return a 64-char hex hash string
  hash_fn: async (blobHex) => await crypto.cn_pico(blobHex)
})

const scheduler = create_pow_scheduler()
const rate_policy = create_rate_policy()

export async function challenge_message({ get_job, message_hash }) {
  return await message_challenge({
    get_job,
    backend,
    message_hash,
    required_shares: 1,
    nonce_tag_bits: 4,
    scheduler,
    rate_policy
  })
}
```

Performance note: this is simplest to integrate, but can be significantly slower if `cn_pico()` is called over the classic RN bridge. Prefer JSI/TurboModules for high call rates, or implement the native batch-scan `findShare()` API for best performance.
