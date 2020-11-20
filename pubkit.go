package pubkit

import (
	"github.com/speier/pubkit/internal/proto"
	"github.com/speier/pubkit/internal/x25519"
)

// must generate x25519 key pair
func GenerateKeys() ([]byte, []byte) {
	pubkey, prvkey, err := x25519.GenerateKeys()
	if err != nil {
		panic(err)
	}
	return pubkey, prvkey
}

func Seal(data []byte, pubkey ...[]byte) *proto.Envelope {
	envelope, err := x25519.Seal(data, pubkey...)
	if err != nil {
		panic(err)
	}
	return envelope
}

func Open(envelope *proto.Envelope, prvkey []byte) []byte {
	res, err := x25519.Open(envelope, prvkey)
	if err != nil {
		panic(err)
	}
	return res
}
