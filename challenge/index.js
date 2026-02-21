module.exports = {
  ...require('./core'),
  ...require('./backends/native_batch'),
  ...require('./backends/js_hashfn')
}

