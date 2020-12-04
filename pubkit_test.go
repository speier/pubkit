package pubkit

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	// generate public/private key pairs
	aPub, _ := mustGenKeys(t)
	bPub, bPrv := mustGenKeys(t)

	// encrypt for both 'a' and 'b' with public keys
	want := []byte("hello")
	secret, err := Seal(want, aPub, bPub)
	if err != nil {
		t.Error(err)
	}

	// decrypt for 'b' with private key
	doc, err := Open(secret, bPrv)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(doc, want) != 0 {
		t.Errorf("got %s, want %s", doc, want)
	}
}

func mustGenKeys(t *testing.T) ([]byte, []byte) {
	pub, prv, err := GenerateKeys()
	if err != nil {
		t.Error(err)
	}
	return pub, prv
}
