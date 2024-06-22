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
Ensure that you installed the submodule by:
```bash
git submodule update --init
```

### Bitcoin Node
Use Dockerfile to run bitcoin node using bitcoin-core. node/bitcoin.conf can be used as bitcoin config to run regtest with rpcuser walle and pwd password.

``` bash
docker build -t btcnode .
docker volume create btcnode
docker run --rm --name btcnode -v btcnode:/bitcoin-25.0/data -p 18444:18443 btcnode
```

For mac users use this code to build docker image.
``` bash
docker build -t btcnode -f Dockerfile.arm .
```

The first time you run the node you need to create a new wallet (it is no longer created automatically, if the walle was already created use loadwallet) then you can getnewaddress.

``` bash
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 createwallet walle
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 getnewaddress
```

Test bitcoin node from outside container:
```bash
curl --verbose -L --user walle --data-binary '{"jsonrpc": "1.0", "id": "walle", "method": "getblockchaininfo", "params": []}' -H 'content-type: text/plain;' 0.0.0.0:18444
```

### Contributing
Join [WALL•E's Discord channel](https://discord.gg/9e9qnzQAH6) to chat with the contributors and understand next steps, available tasks and bugs to be fixed.


### TODO
- [x] BIP39 (Mnemonic generation)
- [x] BIP32 (HD Wallets)
- [x] Serialized Extendend Private/Public Key (https://learnmeabitcoin.com/technical/keys/hd-wallets/extended-keys/)
- [x] BIP38 (Encrypting Bitcoin Private Key)
- [x] BIP44
- [x] P2PK and P2SH Address Generation
- [ ] Wallet files
- [x] ECDSA Signatures
- [ ] Segwit
- [ ] BTC Node integration
- [ ] Wallet Sync
- [ ] Transactions
- [ ] CLI
- [ ] Taproot
