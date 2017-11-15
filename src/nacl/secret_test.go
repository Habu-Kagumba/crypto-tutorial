package nacl

import (
	"bytes"
	"testing"
)

var (
	testMessage = []byte("This is the test message.")
	testKey     *[32]byte
)

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestEncrypt(t *testing.T) {
	ct, err := Encrypt(testKey, testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pt, err := Decrypt(testKey, ct)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(testMessage, pt) {
		t.Fatalf("Message don't match")
	}
}
