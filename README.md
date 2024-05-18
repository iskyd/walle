# WALL•E

Wall•E is a Bitcoin Wallet written in Zig. 

> **WARNING**: This is just an attempt to learn Bitcoin and Zig. Do not use this project with real BTC.

#### Run
Run src/main.zig
``` bash
zig build run
```
Run src/p.zig (used for debugging)

``` bash
zig build run-p
```

#### Testing
``` bash
zig build test
zig build test --summary all -- src/bip39/bip39.zig src/bip38/bip38.zig
```

### Lib
External libraries such as base58 and clap are installed as git submodule and added to build.zig

### Dev Environment
See devbox.json
``` bash
devbox shell
```

### Bitcoin Node
Use Dockerfile to run bitcoin node using bitcoin-core. node/bitcoin.conf can be used as bitcoin config to run regtest with rpcuser walle and pwd password.

``` bash
docker build -t btcnode .
docker volume create btcnode
docker run --rm --name btcnode -v btcnode:/bitcoin-25.0/data btcnode
```

The first time you run the node you need to create a new wallet (it is no longer created automatically, if the walle was already created use loadwallet) then you can getnewaddress.

``` bash
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 createwallet walle
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 getnewaddress
```


### TODO
- [x] BIP39 (Mnemonic generation)
- [x] BIP32 (HD Wallets)
- [ ] BIP32 (Serialized Extendend Private/Public Key https://learnmeabitcoin.com/technical/keys/hd-wallets/extended-keys/)
- [x] BIP38 (Encrypting Bitcoin Private Key)
- [ ] BIP44
- [x] P2PK and P2SH Address Generation (need to fix network)
- [ ] Wallet files
- [ ] ECDSA Signagures
- [ ] Segwit
- [ ] BTC Node integration
- [ ] Wallet Sync
- [ ] Transactions
- [ ] CLI
- [ ] Taproot
