# Blake2s

This module is a pure luajit implementation of the [blake2](https://blake2.net/)
hashing algorithm.  This modern hash is very fast and secure.  Efforts have been
made to make this implementation fast by using luajit's FFI ctypes and native bitops.

The 32-bit variant of blake2 was used instead of the sometimes faster 64-bit version (blake2b) because luajit doesn't have native bit operations for 64-bit integers and would require either implementing the operations in lua or wrapping
them in C and calling via the FFI (which brings in a native dependency).

Also the 32-bit version of the hashing algorithm is faster on 32-bit CPUs and
should be much faster here due to the bitops being native.

This was developed to aid in portable content-addressable network protocols and
filesystems for luvi apps, but it can be used anywhere where a strong hash is
needed.

## Install

This is published to the public [lit.luvit.io](https://luvit.io/lit.html#name:blake2s%20author:creationix) repository.  Simple add `creationix/blake2s` to your dependencies or
`lit install` it directly.

## `Blake2s.hash(data, outlen=32, key=nil, form=ctype) -> hash`

If you simply need to hash a piece of data, this convenience function is what
you want.  Blake2 is a configurable algorithm.  The hash size can be anything between 1 and 32 bytes long.  An optional key gives keyed HMAC properties.
The output form can be `string`, `hex` or default as a ctype `uint8_t[outlen]`

``lua
local Blake2s = require 'blake2s'

local data = "Hello World\n"
local hash = Blake2s.hash(data, 32, nil, 'hex')
p {
  data = data,
  hash = hash
}
```

Output:

```lua
{ data = 'Hello World\n',
  hash = 'cd0b3b1832c2460e30bc924ebba398f5bf6447478c2532995d4657707340c09c'
}
```

## `Blake2s.new(outlen=32, key=nil) -> ctype<blake2s_ctx>`

If you want to hash a very large piece of data or a stream, this is the
interface for you.  It lets you create a context that can have data
pumped into it.

- `ctx:update(data)` - Add a piece of data to the ongoing hash calculation.
- `ctx:digest(form) -> hash` - Finish the digest and output the final hash.

```lua
local Blake2s = require 'blake2s'

local ctx = Blake2s.new()

ctx:update 'Hello '
ctx:update 'World\n'
local hash = ctx:digest 'hex'

p { hash = hash }
```

Output:

```lua
{ hash = 'cd0b3b1832c2460e30bc924ebba398f5bf6447478c2532995d4657707340c09c' }
```
