package nacl

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// 32 byte key & 24 byte Nonce
const (
	KeySize   = 32
	NonceSize = 24
)

// GenerateKey generates a random secrete Key
func GenerateKey() (*[KeySize]byte, error) {
	key := new([KeySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateNonce generates a new random nonce
func GenerateNonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

var (
	errEncrypt = errors.New("secret: encryption failed")
	errDecrypt = errors.New("secret: decryption failed")
)

// Encrypt generates a random Nonce and encrypts the the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
// A sealed message will be the same size as the original message plus
// secretbox.Overhead bytes long.
func Encrypt(key *[KeySize]byte, message []byte) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, errEncrypt
	}

	output := make([]byte, len(nonce))
	copy(output, nonce[:])
	output = secretbox.Seal(output, message, nonce, key)

	return output, nil
}

// Decrypt extracts nonce from the ciphertext, and attempts to
// decrypt with NaCl secretbox
func Decrypt(key *[KeySize]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < (NonceSize + secretbox.Overhead) {
		return nil, errDecrypt
	}

	var nonce [NonceSize]byte
	copy(nonce[:], ciphertext[:NonceSize])
	output, ok := secretbox.Open(nil, ciphertext[NonceSize:], &nonce, key)
	if !ok {
		return nil, errDecrypt
	}

	return output, nil
}
