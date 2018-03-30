local stdout = require('pretty-print').stdout
local bit = require 'bit'
local ffi = require 'ffi'
local ror = bit.ror
local lshift = bit.lshift
local rshift = bit.rshift
local bxor = bit.bxor
local band = bit.band
local bor = bit.bor
local bnot = bit.bnot
local format = string.format
local char = string.char
local concat = table.concat
local copy = ffi.copy
local fill = ffi.fill
local sizeof = ffi.sizeof
local new = ffi.new

ffi.cdef[[
  typedef struct {
    uint8_t b[64];                      // input buffer
    uint32_t h[8];                      // chained state
    uint32_t t[2];                      // total number of bytes
    size_t c;                           // pointer for b[]
    size_t outlen;                      // digest size
  } blake2s_ctx;
]]

local IV = new('uint32_t[8]', {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
})

local sigma = new('uint8_t[10][16]', {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
})

-- Little-endian byte access.
local function get32(ptr)
  return bor(
    ptr[0],
    lshift(ptr[1], 8),
    lshift(ptr[2], 16),
    lshift(ptr[3], 24)
  )
end

local new_ctx

local function dump(header, data, w)
  stdout:write(header)
  for i = 0, w - 1 do
    stdout:write(format(' %08X', data[i]))
    if i % 6 == 5 then
      stdout:write '\n               '
    end
  end
  stdout:write '\n\n'
end

local v = new 'uint32_t[16]'
local m = new 'uint32_t[16]'

-- Mixing function G.
local function G(a, b, c, d, x, y)
    v[a] = v[a] + v[b] + x
    v[d] = ror(bxor(v[d], v[a]), 16)
    v[c] = v[c] + v[d]
    v[b] = ror(bxor(v[b], v[c]), 12)
    v[a] = v[a] + v[b] + y
    v[d] = ror(bxor(v[d], v[a]), 8)
    v[c] = v[c] + v[d]
    v[b] = ror(bxor(v[b], v[c]), 7)
end

local function ROUND(i)
  -- dump(string.format(' (i=%d)  v[16] =', i), v, 16)
  G(0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]])
  -- dump(string.format(' (i=%d)     v1 =', i), v, 16)
  G(1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]])
  -- dump(string.format(' (i=%d)     v2 =', i), v, 16)
  G(2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]])
  -- dump(string.format(' (i=%d)     v3 =', i), v, 16)
  G(3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]])
  -- dump(string.format(' (i=%d)     v4 =', i), v, 16)
  G(0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]])
  -- dump(string.format(' (i=%d)     v5 =', i), v, 16)
  G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]])
  -- dump(string.format(' (i=%d)     v6 =', i), v, 16)
  G(2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]])
  -- dump(string.format(' (i=%d)     v7 =', i), v, 16)
  G(3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]])
  -- dump(string.format(' (i=%d)     v8 =', i), v, 16)
end

local Blake2s = {}

function Blake2s:compress(is_last)

  for i = 0, 7 do -- init work variables
    v[i] = self.h[i]
    v[i + 8] = IV[i]
  end

  v[12] = bxor(v[12], self.t[0]) -- low 32 bits of offset
  v[13] = bxor(v[13], self.t[1]) -- high 32 bits

  if is_last then -- last block flag set ?
    v[14] = bnot(v[14])
  end

  for i = 0, 15 do -- get little-endian words
    m[i] = get32(self.b + 4 * i)
  end

  -- dump('        m[16] =', m, 16)

  for i = 0, 9 do -- ten rounds
    ROUND(i)
  end

  -- dump(' (i=10) v[16] =', v, 16)

  for i = 0, 7 do
    self.h[i] = bxor(self.h[i], v[i], v[i + 8])
  end

  -- dump('         h[8] =', self.h, 8)

end

function Blake2s.new(outlen, key)
  if not outlen then outlen = 32 end
  assert(type(outlen) == 'number' and outlen > 0 and outlen <= 32)
  if type(key) == 'string' then key = new('uint8_t[?]', #key, key) end
  local keylen = key and sizeof(key) or 0

  local ctx = new_ctx()

  copy(ctx.h, IV, sizeof(IV)) -- state, "param block"

  ctx.h[0] = bxor(ctx.h[0], 0x01010000, lshift(keylen, 8), outlen)
  ctx.t[0] = 0 -- input count low word
  ctx.t[1] = 0 -- input count high word
  ctx.c = 0    -- pointer within buffer
  ctx.outlen = outlen

  if keylen > 0 then
      ctx:update(key)
      ctx.c = 64 -- at the end
  end

  return ctx
end

function Blake2s:update(input)
  if type(input) == 'string' then
    input = new('uint8_t[?]', #input, input)
  end

  for i = 0, sizeof(input) - 1 do
    if self.c == 64 then
      self.t[0] = self.t[0] + self.c
      if self.t[0] < self.c then
        self.t[1] = self.t[1] + 1
      end
      self.c = 0
      self:compress(false)
    end
    self.b[self.c] = input[i]
    self.c = self.c + 1
  end
end

function Blake2s:digest(form)
  self.t[0] = self.t[0] + self.c
  if self.t[0] < self.c then
    self.t[1] = self.t[1] + 1
  end


  while self.c < 64 do -- fill up with zeros
    self.b[self.c] = 0
    self.c = self.c + 1
  end

  self:compress(true)

  -- little endian convert and store
  local out = new('uint8_t[?]', self.outlen)
  for i = 0, tonumber(self.outlen) - 1 do
    out[i] = rshift(self.h[rshift(i, 2)], 8 * band(i, 3))
  end

  if form == 'string' then
    return ffi.string(out, self.outlen)
  end
  if form == 'hex' then
    local hex = {}
    for i = 1, tonumber(self.outlen) do
      hex[i] = format("%02x", out[i - 1])
    end
    return concat(hex)
  end
  return out
end

new_ctx = ffi.metatype('blake2s_ctx', { __index = Blake2s })

local function test(input, key, expected)
  local raw = input:gsub('..', function (b)
    return char(tonumber(b, 16))
  end)
  if key then
    key = key:gsub('..', function (b)
      return char(tonumber(b, 16))
    end)
  end
  local b = Blake2s.new(32, key)
  b:update(raw)
  local output = b:digest 'hex'
  p(#raw)
  print(expected)
  print(output)
  assert(expected == output)
end

test(
  "",
  nil,
  "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
)
test(
  "61",
  nil,
  "4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90"
)
test(
  "616263",
  nil,
  "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
)
test(
  "6d65737361676520646967657374",
  nil,
  "fa10ab775acf89b7d3c8a6e823d586f6b67bdbac4ce207fe145b7d3ac25cd28c"
)
test(
  "6162636465666768696a6b6c6d6e6f707172737475767778797a",
  nil,
  "bdf88eb1f86a0cdf0e840ba88fa118508369df186c7355b4b16cf79fa2710a12"
)
test(
  "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839",
  nil,
  "c75439ea17e1de6fa4510c335dc3d3f343e6f9e1ce2773e25b4174f1df8b119b"
)
test(
  "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930",
  nil,
  "fdaedb290a0d5af9870864fec2e090200989dc9cd53a3c092129e8535e8b4f66"
)

coroutine.wrap(function ()
  local vectors = require('coro-fs').readFile('blake2s-kat.txt')
  for input, key, hash in vectors:gmatch("%s*in:%s*([^%s]+)%s*key:%s*([^%s]+)%s*hash:%s*([^%s]+)") do
    test(input, key, hash)
  end
  -- print(vectors)
end)()
