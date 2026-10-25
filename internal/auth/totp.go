package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func ParseTOTPSecret(s string) ([]byte, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(strings.ReplaceAll(s, " ", ""), "=")))
	if err != nil || len(key) < 10 {
		return nil, errors.New("TOTP secret must be base32 and at least 80 bits")
	}
	return key, nil
}

func TOTPURI(secret string) string {
	return "otpauth://totp/tinyvault:admin?secret=" + secret + "&issuer=tinyvault"
}

func totpCode(key []byte, counter uint64) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[off:])&0x7fffffff%1_000_000)
}

type totp struct {
	mu   sync.Mutex
	key  []byte
	last uint64
	now  func() time.Time
}

// verify accepts a code from the current 30s step or one either side, and never the same step twice.
func (t *totp) verify(code string) bool {
	step := uint64(t.now().Unix()) / 30
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range []uint64{step - 1, step, step + 1} {
		if c > t.last && subtle.ConstantTimeCompare([]byte(totpCode(t.key, c)), []byte(code)) == 1 {
			t.last = c
			return true
		}
	}
	return false
}
