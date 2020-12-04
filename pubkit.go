package pubkit

import (
	"errors"

	"github.com/speier/pubkit/internal/x25519"
	"github.com/speier/pubkit/pkg/envelope"
)

func GenerateKeys() ([]byte, []byte, error) {
	pubkey, prvkey, err := x25519.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	return pubkey, prvkey, nil
}

func Seal(data []byte, pubkey ...[]byte) (*envelope.Envelope, error) {
	if len(pubkey) == 0 {
		return nil, errors.New("one or more public key must be specified")
	}

	envelope, err := x25519.Seal(data, pubkey...)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

func Open(envelope *envelope.Envelope, prvkey []byte) ([]byte, error) {
	res, err := x25519.Open(envelope, prvkey)
	if err != nil {
		return nil, err
	}

	return res, nil
}
