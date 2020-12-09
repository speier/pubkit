package x25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/speier/pubkit/internal/primitives"
	"github.com/speier/pubkit/pkg/envelope"
)

const keySize = 32

var b64 = base64.RawStdEncoding.Strict()

// generate new public/private key pair
func GenerateKeys() ([]byte, []byte, error) {
	prvkey := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(prvkey)
	if err != nil {
		return nil, nil, err
	}

	pubkey, err := curve25519.X25519(prvkey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return pubkey, prvkey, nil
}

// seal data with recipients public key
func Seal(data []byte, pubkey ...[]byte) (*envelope.Envelope, error) {
	masterKey := make([]byte, keySize)
	_, err := rand.Read(masterKey)
	if err != nil {
		return nil, err
	}

	recipients := make([]*envelope.Recipient, 0)
	for _, rpubkey := range pubkey {
		ephemeralPub, ephemeralPrv, err := GenerateKeys()
		if err != nil {
			return nil, err
		}

		sharedSecret, err := getSharedSecret(ephemeralPrv, rpubkey)
		if err != nil {
			return nil, err
		}

		wrapKey, err := deriveWrapKey(sharedSecret, ephemeralPub, rpubkey)
		if err != nil {
			return nil, err
		}

		rcptsKey, err := primitives.EncryptAEAD(wrapKey, masterKey)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, &envelope.Recipient{
			PubKey:  b64.EncodeToString(rpubkey),
			EPubKey: b64.EncodeToString(ephemeralPub),
			DocKey:  rcptsKey,
		})
	}

	encBody, err := primitives.EncryptAEAD(masterKey, data)
	if err != nil {
		return nil, err
	}

	return envelope.NewEnvelope(envelope.V1, recipients, encBody), nil
}

// open data with private key
func Open(envelope *envelope.Envelope, prvkey []byte) ([]byte, error) {
	// pub derived from priv
	pubkey, err := curve25519.X25519(prvkey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	for _, r := range envelope.Recipients {
		rpubkey, err := b64.DecodeString(r.EPubKey)
		if err != nil {
			continue
		}

		sharedSecret, err := getSharedSecret(prvkey, rpubkey)
		if err != nil {
			return nil, err
		}

		wrapKey, err := deriveWrapKey(sharedSecret, rpubkey, pubkey)
		if err != nil {
			return nil, err
		}

		bodyKey, err := primitives.DecryptAEAD(wrapKey, r.DocKey)
		if err != nil {
			continue
		}

		decBody, err := primitives.DecryptAEAD(bodyKey, envelope.Body)
		if err != nil {
			continue
		}

		return decBody, nil
	}

	return nil, nil
}

// open with private key and update data
func Update(envelope *envelope.Envelope, prvkey []byte, data []byte) (*envelope.Envelope, error) {
	// check if user can open
	_, err := Open(envelope, prvkey)
	if err != nil {
		return nil, err
	}

	// collect existing recipients keys
	rcptkeys := make([][]byte, 0)
	for _, rcpt := range envelope.Recipients {
		rpk, err := b64.DecodeString(rcpt.PubKey)
		if err != nil {
			return nil, err
		}
		rcptkeys = append(rcptkeys, rpk)
	}

	return Seal(data, rcptkeys...)
}

// open with private key and append one or more recipients' public key
func Append(envelope *envelope.Envelope, prvkey []byte, pubkey ...[]byte) (*envelope.Envelope, error) {
	data, err := Open(envelope, prvkey)
	if err != nil {
		return nil, err
	}

	// collect existing recipients keys
	rcptkeys := make([][]byte, 0)
	for _, rcpt := range envelope.Recipients {
		rpk, err := b64.DecodeString(rcpt.PubKey)
		if err != nil {
			return nil, err
		}
		rcptkeys = append(rcptkeys, rpk)
	}

	// append new recipients if not exists
	for _, pubk := range pubkey {
		if !contains(rcptkeys, pubk) {
			rcptkeys = append(rcptkeys, pubk)
		}
	}

	return Seal(data, rcptkeys...)
}

func getSharedSecret(prvkey, pubkey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(prvkey, pubkey)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

func deriveWrapKey(sharedSecret, ephemeralPub, pubkey []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephemeralPub)+len(pubkey))
	salt = append(salt, ephemeralPub...)
	salt = append(salt, pubkey...)

	h := hkdf.New(sha256.New, sharedSecret, salt, nil)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}

	return key, nil
}

func contains(in [][]byte, a []byte) bool {
	for _, b := range in {
		if bytes.Compare(a, b) == 0 {
			return true
		}
	}
	return false
}
