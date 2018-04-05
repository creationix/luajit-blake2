local char = string.char

local Blake2s = require './blake2s'
local Blake2b = require './blake2b'

local function tests(input, key, expected)
  local output = Blake2s.hash(input, 32, key, 'hex')
  p(#input)
  print(expected)
  print(output)
  assert(expected == output)
  collectgarbage("collect")
end

local function testb(input, key, expected)
  local output = Blake2b.hash(input, 64, key, 'hex')
  p(#input)
  print(expected)
  print(output)
  assert(expected == output)
  collectgarbage("collect")
end

coroutine.wrap(function ()
  local vectors = require('coro-fs').readFile('blake2s-kat.txt')
  for input, hash in vectors:gmatch("Message:%s*\"([^%s]+)\"%s*Digest:%s*([^%s]+)") do
    tests(input, nil, hash:lower())
  end
  for input, key, hash in vectors:gmatch("in:%s*([^%s]+)%s*key:%s*([^%s]+)%s*hash:%s*([^%s]+)") do
    tests(input:gsub('..', function (b)
      return char(tonumber(b, 16))
    end), key:gsub('..', function (b)
      return char(tonumber(b, 16))
    end), hash)
  end
  vectors = require('coro-fs').readFile('blake2b-kat.txt')
  for input, key, hash in vectors:gmatch("in:%s*([^%s]+)%s*key:%s*([^%s]+)%s*hash:%s*([^%s]+)") do
    testb(input:gsub('..', function (b)
      return char(tonumber(b, 16))
    end), key:gsub('..', function (b)
      return char(tonumber(b, 16))
    end), hash)
  end
end)()
