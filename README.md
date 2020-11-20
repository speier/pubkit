# pubkit

Secure encryption library, provides cryptographic APIs to encrypt and authenticate messages with public-key cryptography.


## API example

Public-key authenticated encryption uses Curve25519 and Poly1305 to encrypt and authenticate messages, high-level example:

```go
// generate new public/private key pairs
aPub, aPrv := pubkit.GenerateKey()
bPub, bPrv := pubkit.GenerateKey()
cPub, cPrv := pubkit.GenerateKey()

// encrypt for 'a' and 'b' with public keys
secret := pubkit.Seal("hello", aPub, bPub)

// later share with 'c' as well
secret := pubkit.Append(secret, cPub)

// then 'c' opens secret with private key
doc := pubkit.Open(secret, cPrv)
fmt.Println(doc)
```

## Protocol

[wip]

```txt
sender <pubkey> <dockey encrypted with pubkey>
---
rcpt.1 <pubkey> <dockey encrypted with pubkey>
...
rcpt.n <pubkey> <dockey encrypted with pubkey>
---
<message encrypted with dockey>
```
