# Examples using bx

Seed: fc795be0c3f18c50dddb34e72179dc597d64055497ecc1e69e2e56a5409651bc139aae8070d4df0ea14d8d2a518a9a00bb1cc6e92e053fe34051f6821df9164c

#### Generate private key

```bash
bx ec-new fc795be0c3f18c50dddb34e72179dc597d64055497ecc1e69e2e56a5409651bc139aae8070d4df0ea14d8d2a518a9a00bb1cc6e92e053fe34051f6821df9164c
```

Private key:
b39586851d52222a098455b1283de23b3b984da16a492d96a4f62189677b8495

#### Generate public key

```bash
bx ec-new fc795be0c3f18c50dddb34e72179dc597d64055497ecc1e69e2e56a5409651bc139aae8070d4df0ea14d8d2a518a9a00bb1cc6e92e053fe34051f6821df9164c | bx ec-to-public
```

Public key: 03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5

#### Generate address

```bash
echo "03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5" | bx sha256 | bx ripemd160
```

Res: 286fd267876fb1a24b8fe798edbc6dc6d5e2ea5b
Add version (00 for wallet address)
Res: 00286fd267876fb1a24b8fe798edbc6dc6d5e2ea5b
Calculate the checksum (4 bytes of)

```bash
echo "00286fd267876fb1a24b8fe798edbc6dc6d5e2ea5b" | bx sha256 | bx sha256
```

Res: d4bc14821728063c8c2a6454be521faf4d704f39fd07c20d6ee4a26ed5976d86
Checksum: d4bc1482
Calculate the address using base-58 encode

```bash
echo "00286fd267876fb1a24b8fe798edbc6dc6d5e2ea5bd4bc1482" | bx base58-encode
```

This show the complete process of generate an address from the public key, alternatively

```bash
echo "03525cbe17e87969013e6457c765594580dc803a8497052d7c1efb0ef401f68bd5" | bx ec-to-address
```

#### Generate WIF

```bash
bx ec-to-wif b39586851d52222a098455b1283de23b3b984da16a492d96a4f62189677b8495
```
