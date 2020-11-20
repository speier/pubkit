package x25519

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/speier/pubkit/internal/primitives"
	"github.com/speier/pubkit/internal/proto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const fileKeySize = 32

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

// seal data with recipients pub key
func Seal(data []byte, pubkey ...[]byte) (*proto.Envelope, error) {
	fileKey := make([]byte, fileKeySize)
	_, err := rand.Read(fileKey)
	if err != nil {
		return nil, err
	}

	recipients := make([]*proto.Recipient, 0)
	for _, rpubkey := range pubkey {
		ephemeralPub, ephemeralPrv, err := GenerateKeys()
		if err != nil {
			return nil, err
		}

		sharedSecret, err := calcSharedSecret(ephemeralPrv, rpubkey)
		if err != nil {
			return nil, err
		}

		wrappingKey, err := makeWrappingKey(sharedSecret, ephemeralPub, rpubkey)
		if err != nil {
			return nil, err
		}

		wrappedKey, err := primitives.EncryptAEAD(wrappingKey, fileKey)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, &proto.Recipient{
			PubKey: b64.EncodeToString(ephemeralPub),
			DocKey: wrappedKey,
		})
	}

	encBody, err := primitives.EncryptAEAD(fileKey, data)
	if err != nil {
		return nil, err
	}

	return &proto.Envelope{
		Recipients: recipients,
		Body:       encBody,
	}, nil
}

// open data with private key
func Open(envelope *proto.Envelope, prvkey []byte) ([]byte, error) {
	// pub calced from priv
	pubkey, err := curve25519.X25519(prvkey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	for _, r := range envelope.Recipients {
		rpubkey, err := b64.DecodeString(r.PubKey)
		if err != nil {
			continue
		}

		sharedSecret, err := calcSharedSecret(prvkey, rpubkey)
		if err != nil {
			return nil, err
		}

		wrappingKey, err := makeWrappingKey(sharedSecret, rpubkey, pubkey)
		if err != nil {
			return nil, err
		}

		fileKey, err := primitives.DecryptAEAD(wrappingKey, r.DocKey)
		if err != nil {
			continue
		}

		decBody, err := primitives.DecryptAEAD(fileKey, envelope.Body)
		if err != nil {
			fmt.Println(err)
			continue
		}

		return decBody, nil
	}

	return nil, nil
}

func calcSharedSecret(prvkey, pubkey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(prvkey, pubkey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

func makeWrappingKey(sharedSecret, ephemeralPub, pubkey []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephemeralPub)+len(pubkey))
	salt = append(salt, ephemeralPub...)
	salt = append(salt, pubkey...)

	h := hkdf.New(sha256.New, sharedSecret, salt, nil)
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	return wrappingKey, nil
}
