# WALL•E

Wall•E is a Bitcoin Wallet written in Zig.

> **WARNING**: Do not use this project with real BTC. It is not secure (yet)! The cryptographic part is built from scratch and it is not audited.

### Project

This project will produce 3 executables:

- walle: Bitcoin wallet CLI.
- indexer: This is the bitcoin blockchain indexer. It will only saves locally (in an sqlite db) the relevant transactions/outputs/inputs.
- wbx: Command line utility for Bitcoin (the name is inspired by [libbitcoin-explorer](https://github.com/libbitcoin/libbitcoin-explorer))

#### Build the project

``` bash
zig build
```

You can also specify `--release=<release mode>`. Check the [Zig Docs](https://ziglang.org/learn/build-system/) for more information.

#### Testing

``` bash
zig build test
zig build test --summary all -- src/bip39/bip39.zig src/bip38/bip38.zig
```

#### Dev Environment

##### Devbox

You can directly use devbox to create a complete dev environment. Check devbox.json and [devbox](https://www.jetify.com/devbox) docs for more information.

``` bash
devbox shell
```

##### Nix + devenv

In order to get a shell with all the tools you need to contribute to this project you can run

```bash
direnv allow
```

This will enable the `direnv` environment that will automatically makes you enter the development shell every time you enter the project directory (or any subdirectory). This uses [nix](https://nixos.org/download/) (with [flakes](https://nixos.wiki/wiki/Flakes)) and [direnv](https://direnv.net).

This command

```bash
nix flake check
```

will run regular checks of the flake, in particular it will run _git hooks_.
This runs in the GHA `flake-check` job.

###### Git hooks

The `nix` shell will install the git hooks automatically.
The pre-commit configuration `.pre-commit-config.yaml` is git-ignored because it will be a simple
link to the `/nix/store`: the semantic is not changing but the location can differ from different
machines/configuration.

You can manually trigger the hooks on all files:

```bash
pre-commit run -a
```

Check the `--help` for more usages.

#### Bitcoin Node

walle needs a bitcoin-core node. You can run one using the Dockerfile. The configuration is defined in node/bitcoin.conf and it is used to create a regtest network.

``` bash
docker build -t btcnode .
docker volume create btcnode
docker run --rm --name btcnode -v btcnode:/bitcoin-25.0/data -p 18444:18443 btcnode
```

#### Regtest

Enter inside the `btcnode` container:

```bash
docker exec -ti btcnode bash
```

The first time you run the node you need to create a new wallet (it is no longer created automatically, if the walle was already created use loadwallet) then you can getnewaddress and mine some blocks.

``` bash
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 createwallet walle
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 getnewaddress
bitcoin-cli -rpcuser=walle -rpcpassword=password -rpcport=18443 generatetoaddress <nblocks> <address>
```

From outside the container, one can communicate with the `btcnode` via RPC.
Ex: 

```bash
curl --verbose -L --user walle --data-binary '{"jsonrpc": "1.0", "id": "walle", "method": "getblockchaininfo", "params": []}' -H 'content-type: text/plain;' 0.0.0.0:18444
```

### Features

- [x] Crypto (secp256k1, ecdsa signatures, ripemd160, bech32). Everything is built from scratch.
- [x] Bip39 (Mnemonic generation)
- [x] Bip32 (HD Wallets)
- [x] BIP38 (Encrypting Bitcoin Private Key)
- [x] Bip44
- [x] Serialized Extendend Private/Public Key
- [x] BTC core rpc integration
- [x] Indexer
- [x] Addresses
- [x] Segwit
- [x] Transactions (create/sign)

### Current Roadmap (ordered by priority)

- [ ] Electrum Server
- [ ] [Seed Signer](https://seedsigner.com/)
- [ ] Lightning Network
- [ ] TUI
- [ ] Multisig Wallet
- [ ] Taproot
- [ ] Legacy Wallet

### Contributing

Join [WALL•E's Discord channel](https://discord.gg/9e9qnzQAH6) to chat with the contributors and understand next steps, available tasks and bugs to be fixed.
