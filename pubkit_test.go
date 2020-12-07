package pubkit

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	// generate public/private key pairs
	aPub, _ := MustGenerateKeys()
	bPub, bPrv := MustGenerateKeys()

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

func TestUpdate(t *testing.T) {
	// generate public/private key pairs
	aPub, aPrv := MustGenerateKeys()

	// encrypt for 'a' with public keys
	want := []byte("hello")
	secret, err := Seal(want, aPub)
	if err != nil {
		t.Error(err)
	}

	// update data
	want = []byte("hello-updated")
	secret, err = Update(secret, aPrv, want)

	// decrypt for 'a' with private key
	doc, err := Open(secret, aPrv)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(doc, want) != 0 {
		t.Errorf("got %s, want %s", doc, want)
	}
}

func TestAppend(t *testing.T) {
	// generate public/private key pairs
	aPub, aPrv := MustGenerateKeys()
	bPub, bPrv := MustGenerateKeys()

	// encrypt for 'a'
	want := []byte("hello")
	secret, err := Seal(want, aPub)
	if err != nil {
		t.Error(err)
	}

	// append 'b' pub key
	modsecret, err := Append(secret, aPrv, bPub)
	if err != nil {
		t.Error(err)
	}

	// decrypt for 'b' with private key
	doc, err := Open(modsecret, bPrv)
	if err != nil {
		t.Error(err)
	}

	// decrypt for 'a' with private key
	doc, err = Open(modsecret, aPrv)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(doc, want) != 0 {
		t.Errorf("got %s, want %s", doc, want)
	}
}
