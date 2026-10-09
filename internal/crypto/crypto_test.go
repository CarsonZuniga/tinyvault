package crypto

import "testing"

func TestRoundTripAndAAD(t *testing.T) {
	k := make([]byte, 32)
	b, _ := New(k)
	ct, _ := b.Seal([]byte("hunter2"), "media/prod/DB_PASS")
	if pt, err := b.Open(ct, "media/prod/DB_PASS"); err != nil || string(pt) != "hunter2" {
		t.Fatal("round trip failed")
	}
	if _, err := b.Open(ct, "media/prod/OTHER"); err == nil {
		t.Fatal("AAD mismatch must fail")
	}
	ct[len(ct)-1] ^= 1
	if _, err := b.Open(ct, "media/prod/DB_PASS"); err == nil {
		t.Fatal("tampering must fail")
	}
}
