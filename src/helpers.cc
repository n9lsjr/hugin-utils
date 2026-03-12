#include <napi.h>
#include <string>
#include <cstdint>
#include <cstdio>

static inline uint8_t hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

static inline uint8_t hex_byte(const char *h) {
  return (hex_val(h[0]) << 4) | hex_val(h[1]);
}

static inline uint32_t read_u32_le(const char *hex, int byte_off) {
  int p = byte_off * 2;
  uint32_t r = 0;
  for (int i = 0; i < 4; i++)
    r |= static_cast<uint32_t>(hex_byte(hex + p + i * 2)) << (i * 8);
  return r;
}

static inline uint64_t parse_target(const char *hex, size_t len) {
  if (len != 8) return 0;
  uint32_t raw = read_u32_le(hex, 0);
  if (raw == 0) return 0;
  uint64_t denom = 0xFFFFFFFFULL / static_cast<uint64_t>(raw);
  if (denom == 0) return 0;
  return 0xFFFFFFFFFFFFFFFFULL / denom;
}

static inline uint64_t hash_tail(const char *hex, size_t len) {
  if (len < 64) return UINT64_MAX;
  uint64_t r = 0;
  for (int i = 0; i < 8; i++)
    r |= static_cast<uint64_t>(hex_byte(hex + 48 + i * 2)) << (i * 8);
  return r;
}

static const char HEX_TABLE[] = "0123456789abcdef";

static inline void nonce_hex_le(uint32_t n, char *out) {
  for (int i = 0; i < 4; i++) {
    uint8_t b = (n >> (i * 8)) & 0xFF;
    out[i * 2]     = HEX_TABLE[b >> 4];
    out[i * 2 + 1] = HEX_TABLE[b & 0x0F];
  }
}

// insertNonce(prefix, suffix, nonce) → full blob hex
Napi::Value InsertNonce(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  std::string prefix = info[0].As<Napi::String>().Utf8Value();
  std::string suffix = info[1].As<Napi::String>().Utf8Value();
  uint32_t nonce = info[2].As<Napi::Number>().Uint32Value();

  char nh[8];
  nonce_hex_le(nonce, nh);

  std::string out;
  out.reserve(prefix.size() + 8 + suffix.size());
  out.append(prefix);
  out.append(nh, 8);
  out.append(suffix);
  return Napi::String::New(env, out);
}

// checkHash(hashHex, targetHex) → boolean
Napi::Value CheckHash(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  std::string h = info[0].As<Napi::String>().Utf8Value();
  std::string t = info[1].As<Napi::String>().Utf8Value();
  uint64_t target = parse_target(t.c_str(), t.size());
  if (target == 0) return Napi::Boolean::New(env, false);
  return Napi::Boolean::New(env, hash_tail(h.c_str(), h.size()) <= target);
}

// nonceToHexLE(nonce) → string
Napi::Value NonceToHexLE(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  uint32_t nonce = info[0].As<Napi::Number>().Uint32Value();
  char nh[8];
  nonce_hex_le(nonce, nh);
  return Napi::String::New(env, nh, 8);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("insertNonce", Napi::Function::New(env, InsertNonce));
  exports.Set("checkHash", Napi::Function::New(env, CheckHash));
  exports.Set("nonceToHexLE", Napi::Function::New(env, NonceToHexLE));
  return exports;
}

NODE_API_MODULE(hugin_helpers, Init)
