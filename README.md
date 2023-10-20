# WALL-E

Wall-E is a Bitcoin Wallet written in Zig. 

> **WARNING**: This is just an attempt to learn Bitcoin and Zig. Do not use this project with real BTC.


#### Testing
Single file
```
zig test --mod base58::lib/base58/src/lib.zig --deps base58 src/utils.zig --main-pkg-path .
```

Build test
```
zig build test
```

### Lib
External libraries such as base58 are installed as git submodule and added to build.zig

