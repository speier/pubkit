package pubkit

import (
	"errors"

	"github.com/speier/pubkit/internal/x25519"
	"github.com/speier/pubkit/pkg/envelope"
)

// must generate new public/private key pair
func MustGenerateKeys() ([]byte, []byte) {
	pub, prv, err := GenerateKeys()
	if err != nil {
		panic(err)
	}
	return pub, prv
}

// generate new public/private key pair
func GenerateKeys() ([]byte, []byte, error) {
	pubkey, prvkey, err := x25519.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	return pubkey, prvkey, nil
}

// seal data with recipients public key
func Seal(data []byte, pubkey ...[]byte) (*envelope.Envelope, error) {
	if len(data) == 0 {
		return nil, errors.New("data must be specified")
	}
	if len(pubkey) == 0 {
		return nil, errors.New("one or more public key must be specified")
	}

	envelope, err := x25519.Seal(data, pubkey...)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

// open data with private key
func Open(envelope *envelope.Envelope, prvkey []byte) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("envelope is nil, must be specified")
	}
	if len(prvkey) == 0 {
		return nil, errors.New("private key must be specified")
	}

	res, err := x25519.Open(envelope, prvkey)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New("failed to open")
	}

	return res, nil
}

// open with private key and update data
func Update(envelope *envelope.Envelope, prvkey []byte, data []byte) (*envelope.Envelope, error) {
	if envelope == nil {
		return nil, errors.New("envelope is nil, must be specified")
	}
	if len(prvkey) == 0 {
		return nil, errors.New("private key must be specified")
	}
	if len(data) == 0 {
		return nil, errors.New("data must be specified")
	}

	envelope, err := x25519.Update(envelope, prvkey, data)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

// open with private key and append one or more recipients' public key
func Append(envelope *envelope.Envelope, prvkey []byte, pubkey ...[]byte) (*envelope.Envelope, error) {
	if envelope == nil {
		return nil, errors.New("envelope is nil, must be specified")
	}
	if len(pubkey) == 0 {
		return nil, errors.New("one or more public key must be specified")
	}

	envelope, err := x25519.Append(envelope, prvkey, pubkey...)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}
