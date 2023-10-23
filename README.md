# WALL-E

Wall-E is a Bitcoin Wallet written in Zig. 

> **WARNING**: This is just an attempt to learn Bitcoin and Zig. Do not use this project with real BTC.

#### Run
```
zig run --mod base58::lib/base58/src/lib.zig src/p.zig --deps base58
```


#### Testing
Single file (--main-pkg-path before zig 0.12.0)
```
zig test --mod base58::lib/base58/src/lib.zig --deps base58 src/utils.zig --main-mod-path .
```

Build test
```
zig build test
```

### Lib
External libraries such as base58 and clap are installed as git submodule and added to build.zig

