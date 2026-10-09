package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type Box struct{ aead cipher.AEAD }

func ParseKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes, base64-encoded")
	}
	return key, nil
}

func GenerateKey() string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{aead: g}, nil
}

// Seal encrypts plaintext. aad (e.g. "project/env/KEY") binds the ciphertext
// to its location so values can't be swapped between rows in the DB.
func (b *Box) Seal(plaintext []byte, aad string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

func (b *Box) Open(ct []byte, aad string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(ct) < n {
		return nil, errors.New("ciphertext too short")
	}
	return b.aead.Open(nil, ct[:n], ct[n:], []byte(aad))
}

func Fingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return base64.RawStdEncoding.EncodeToString(h[:6])
}
