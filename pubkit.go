package pubkit

import (
	"encoding/base64"
	"errors"

	"github.com/speier/pubkit/internal/x25519"
	"github.com/speier/pubkit/pkg/envelope"
)

var b64 = base64.RawStdEncoding.Strict()

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
	if envelope == nil {
		return nil, errors.New("envelope is nil, must be specified")
	}

	res, err := x25519.Open(envelope, prvkey)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func Append(envelope *envelope.Envelope, prvkey []byte, pubkey ...[]byte) (*envelope.Envelope, error) {
	if envelope == nil {
		return nil, errors.New("envelope is nil, must be specified")
	}
	if len(pubkey) == 0 {
		return nil, errors.New("one or more public key must be specified")
	}

	data, err := Open(envelope, prvkey)
	if err != nil {
		return nil, err
	}

	for _, rcpt := range envelope.Recipients {
		rpk, err := b64.DecodeString(rcpt.PubKey)
		if err != nil {
			return nil, err
		}
		pubkey = append(pubkey, []byte(rpk))
	}

	return Seal(data, pubkey...)
}
