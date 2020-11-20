# pubkit

Secure encryption library, provides cryptographic APIs to encrypt and authenticate messages with public-key cryptography.

## Usage example

Public-key authenticated encryption uses Curve25519 and Poly1305 to encrypt and authenticate messages, high-level example:

```go
// generate public/private key pairs
aPub, _ := pubkit.GenerateKeys()
bPub, bPrv := pubkit.GenerateKeys()

// encrypt for both 'a' and 'b' with public keys
secret := pubkit.Seal("hello", aPub, bPub)

// decrypt for 'b' with private key
doc := pubkit.Open(secret, bPrv)
fmt.Println(doc)
```
