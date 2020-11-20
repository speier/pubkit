package pubkit

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	// generate public/private key pairs
	aPub, _ := GenerateKeys()
	bPub, bPrv := GenerateKeys()

	// encrypt for both 'a' and 'b' with public keys
	want := []byte("hello")
	secret := Seal(want, aPub, bPub)

	// decrypt for 'b' with private key
	doc := Open(secret, bPrv)

	if bytes.Compare(doc, want) != 0 {
		t.Errorf("got %s, want %s", doc, want)
	}
}
