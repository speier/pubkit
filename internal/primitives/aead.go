package primitives

import (
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptAEAD(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func DecryptAEAD(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}
