local bit = require 'bit'
local ror = bit.ror
local lshift = bit.lshift
local rshift = bit.rshift
local bxor = bit.bxor
local band = bit.band
local bor = bit.bor
local format = string.format
local concat = table.concat

local ffi = require 'ffi'
local C = ffi.C
local copy = ffi.copy
local fill = ffi.fill
local sizeof = ffi.sizeof
local new = ffi.new
local cdef = ffi.cdef
local metatype = ffi.metatype

cdef[[
  enum blake2s_constant {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

  typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2s_state;

]]

local IV = new('uint32_t[8]', {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
})

local sigma = new('uint8_t[10][16]', {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
})

local function G(r, i, m, a, b, c, d)
    a = a + b + m[sigma[r][2 * i]]
    d = ror(bxor(d, a), 16)
    c = c + d
    b = ror(bxor(b, c), 12)
    a = a + b + m[sigma[r][2 * i + 1]]
    d = ror(bxor(d, a), 8)
    c = c + d
    b = ror(bxor(b, c), 7)
    return a, b, c, d
end

local function ROUND(r, m, v)
  v[0], v[4], v[8], v[12] = G(r, 0, m, v[0], v[4], v[8], v[12])
  v[1], v[5], v[9], v[13] = G(r, 1, m, v[1], v[5], v[9], v[13])
  v[2], v[6], v[10], v[14] = G(r, 2, m, v[2], v[6], v[10], v[14])
  v[3], v[7], v[11], v[15] = G(r, 3, m, v[3], v[7], v[11], v[15])
  v[0], v[5], v[10], v[15] = G(r, 4, m, v[0], v[5], v[10], v[15])
  v[1], v[6], v[11], v[12] = G(r, 5, m, v[1], v[6], v[11], v[12])
  v[2], v[7], v[8], v[13] = G(r, 6, m, v[2], v[7], v[8], v[13])
  v[3], v[4], v[9], v[14] = G(r, 7, m, v[3], v[4], v[9], v[14])
end

local State = {}

function State:update(chunk)
  assert(self.f[0] == 0, 'hash already finialized')
  if type(chunk) == 'string' then
    chunk = new('uint8_t[?]', #chunk, chunk)
  end
  local len = sizeof(chunk)
  if len == 0 then return end
  local left = self.buflen
  local tofill = C.BLAKE2S_BLOCKBYTES - left
  if len > tofill then
    self.buflen = 0
    copy(self.buf + left, chunk, tofill)
    self:increment_counter(C.BLAKE2S_BLOCKBYTES)
    self:compress(self.buf)
    chunk = chunk + tofill
    len = len - tofill
    while len > C.BLAKE2S_BLOCKBYTES do
      self:increment_counter(C.BLAKE2S_BLOCKBYTES)
      self:compress(chunk)
      chunk = chunk + C.BLAKE2S_BLOCKBYTES
      len = len - C.BLAKE2S_BLOCKBYTES
    end
  end
  copy(self.buf + self.buflen, chunk, len)
  self.buflen = self.buflen + len
end

function State:digest(outform)
  if self.f[0] == 0 then
    self.f[0] = 1 -- set lastblock

    self:increment_counter(self.buflen)

    fill(self.buf + self.buflen, C.BLAKE2S_BLOCKBYTES - self.buflen, 0)
    self:compress(self.buf)
  end

  local buffer = new 'uint8_t[BLAKE2S_OUTBYTES]'
  for i = 0, 7 do
    local word = self.h[i]
    local o = i * 4
    buffer[o] = band(word, 0xff)
    buffer[o + 1] = band(rshift(word, 8), 0xff)
    buffer[o + 2] = band(rshift(word, 16), 0xff)
    buffer[o + 3] = rshift(word, 24)
  end

  if outform == 'string' then
    return ffi.string(buffer, self.outlen)
  end
  if outform == 'hex' then
    local hex = {}
    for i = 1, tonumber(self.outlen) do
      hex[i] = format("%02x", buffer[i - 1])
    end
    return concat(hex)
  end
  if self.outlen == C.BLAKE2S_OUTBYTES then
    return buffer
  end
  local hash = new('uint8_t[?]', self.outlen)
  copy(hash, buffer, self.outlen)
  return hash
end

function State:increment_counter(inc)
  self.t[0] = self.t[0] + inc
  self.t[1] = self.t[1] + (self.t[0] < inc and 1 or 0)
end

function State:compress(block)
  local m = new 'uint32_t[16]'
  local v = new 'uint32_t[16]'

  for i = 0, 15 do
    local mem = block + i * 4
    m[i] = bor(
      mem[3],
      lshift(mem[2], 8),
      lshift(mem[1], 16),
      lshift(mem[0], 24)
    )
  end

  for i = 0, 7 do
    v[i] = self.h[i]
  end

  v[8] = IV[0]
  v[9] = IV[1]
  v[10] = IV[2]
  v[11] = IV[3]
  v[12] = bxor(self.t[0], IV[4])
  v[13] = bxor(self.t[1], IV[5])
  v[14] = bxor(self.f[0], IV[6])
  v[15] = bxor(self.f[1], IV[7])

  ROUND(0, m, v)
  ROUND(1, m, v)
  ROUND(2, m, v)
  ROUND(3, m, v)
  ROUND(4, m, v)
  ROUND(5, m, v)
  ROUND(6, m, v)
  ROUND(7, m, v)
  ROUND(8, m, v)
  ROUND(9, m, v)

  for i = 0, 7 do
    self.h[i] = bxor(self.h[i], v[i], v[i + 8])
  end
end


metatype('blake2s_state', { __index = State })

local function init(outlen, key)
  if not outlen then outlen = 32 end
  assert(type(outlen) == 'number' and
    outlen > 0 and outlen <= C.BLAKE2S_OUTBYTES, 'Invalid hash length')
  if type(key) == 'string' then
    key = new('uint8_t[?]', #key, key)
  end

  local S = new 'blake2s_state'

  -- Copy IV to reset state
  copy(S.h, IV, sizeof(IV))

  -- Store outlen
  S.outlen = outlen

  -- Mix in shared params
  S.h[0] = bxor(S.h[0], 0x01010000, S.outlen)

  if key then
    -- Mix in keylen param
    local keylen = sizeof(key)
    S.h[0] = bxor(S.h[0], lshift(band(keylen, 0xff), 8))
    -- Apply key as hash block
    local block = new 'uint8_t[BLAKE2S_BLOCKBYTES]'
    copy(block, key, keylen)
    S:update(block)
  end

  return S
end

local input = {
    v1 =  { "" },
    v2 =  { "abc" },
    v3 =  { "test 123" },
    v4 =  { "The quick brown fox jumps over the lazy dog" },
    v5 =  { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, -- string.rep("a", 62)
    v6 =  { "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }, -- string.rep("b", 63)
    v7 =  { "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }, -- string.rep("c", 64)
    v8 =  { "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" }, -- string.rep("d", 65)
    v9 =  { "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }, -- string.rep("e", 66)
    v10 = { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }, -- string.rep("f", 126)
    v11 = { "ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg" }, -- string.rep("g", 127)
    v12 = { "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh" }, -- string.rep("h", 128)
    v13 = { "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii" }, -- string.rep("i", 129)
    v14 = { "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj" }, -- string.rep("j", 130)
}

local expected = {
    v1 =  { "69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9" },
    v2 =  { "508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982" },
    v3 =  { "6FE6A61D36DD4F9BDD3999BD9E35C53ABC650AA1B926FCB5807DE7B5F1704FD1" },
    v4 =  { "606BEEEC743CCBEFF6CBCDF5D5302AA855C256C29B88C8ED331EA1A6BF3C8812" },
    v5 =  { "1109521FEED362D8AC50E28784406E8B8577E9103F74C7DDE7E7C5339A700E9F" },
    v6 =  { "46BA9185AA823559D31B9682338353CB535CBA84648A575E29BE2DD2712F6CBC" },
    v7 =  { "0D61429825CE22866DA7490E1369670E6F61BBCEA831266C96C9C5886A1481AF" },
    v8 =  { "B39A9D609FED058837E9D4F85BFC5723A67C01B98919086B3D4835D7C3F2E05D" },
    v9 =  { "BEDB9C535E5D6AD5B77D26D51A456C0A36E1C2AA9B6135A91A97E6559BB91E36" },
    v10 = { "F45DD7BFF0254F6DBE717F8D34B294BEEF0B63301C7465539E720E6C2CADAC43" },
    v11 = { "7C1556AB3B3E4A511605AEE6431D5B1241351A40C82689731884FC1016581B49" },
    v12 = { "3944F8F3203D6F46EFA0C094CC1E1DCAB26B8315584BE1190A8F44A3589AB87F" },
    v13 = { "EFA4CF2F94691527C94550516BF0516B97A47A3993338E48C520939B86E433F2" },
}

for k, v in pairs(input) do
  local h = init()
  local data = unpack(v)
  h:update(data)
  print()
  print(h:digest('hex'))
  local e = unpack(expected[k])
  print(e:lower())
end
