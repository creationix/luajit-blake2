local char = string.char

local Blake2s = require './blake2s'

local function test(input, key, expected)
  local output = Blake2s.hash(input, 32, key, 'hex')
  p(#input)
  print(expected)
  print(output)
  assert(expected == output)
  collectgarbage("collect")
end

coroutine.wrap(function ()
  local vectors = require('coro-fs').readFile('blake2s-kat.txt')
  for input, hash in vectors:gmatch("Message:%s*\"([^%s]+)\"%s*Digest:%s*([^%s]+)") do
    test(input, nil, hash:lower())
  end
  for input, key, hash in vectors:gmatch("in:%s*([^%s]+)%s*key:%s*([^%s]+)%s*hash:%s*([^%s]+)") do
    test(input:gsub('..', function (b)
      return char(tonumber(b, 16))
    end), key:gsub('..', function (b)
      return char(tonumber(b, 16))
    end), hash)
  end
end)()
