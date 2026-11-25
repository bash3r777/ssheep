package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	ap, as, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bp, bs, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ap, as, bp, bs
}

func establish(t *testing.T) (*Session, *Session) {
	t.Helper()
	aPub, aPriv, bPub, bPriv := keys(t)
	w1, pending, err := Initiate(aPriv, "aaaa", "bbbb")
	if err != nil {
		t.Fatal(err)
	}
	w2, b, err := Respond(bPriv, "bbbb", "aaaa", aPub, w1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := pending.Complete(bPub, w2)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestSessionCarriesBothDirections(t *testing.T) {
	a, b := establish(t)

	ct, err := a.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("got %q", got)
	}

	ct, err = b.Seal([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	got, err = a.Open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("world")) {
		t.Fatalf("got %q", got)
	}
}

func TestManyMessagesInOrder(t *testing.T) {
	a, b := establish(t)
	for i := 0; i < 64; i++ {
		want := []byte("message")
		ct, err := a.Seal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := b.Open(ct)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d: got %q", i, got)
		}
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	a, b := establish(t)
	ct, err := a.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x01
	if _, err := b.Open(ct); err == nil {
		t.Fatal("a tampered ciphertext decrypted")
	}
}

func TestReplayedFrameIsRejected(t *testing.T) {
	a, b := establish(t)
	ct, err := a.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(ct); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(append([]byte(nil), ct...)); err == nil {
		t.Fatal("a replayed frame was accepted")
	}
}

func TestOutOfOrderFrameIsRejected(t *testing.T) {
	a, b := establish(t)
	one, err := a.Seal([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := a.Seal([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(two); err == nil {
		t.Fatal("an out of order frame was accepted")
	}
	if _, err := b.Open(one); err != nil {
		t.Fatalf("the in-order frame was rejected: %v", err)
	}
}

func TestImpostorHandshakeIsRejected(t *testing.T) {
	aPub, _, _, bPriv := keys(t)
	_, impostorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The impostor claims to be "aaaa" but signs with a key that is not a's.
	w1, _, err := Initiate(impostorPriv, "aaaa", "bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Respond(bPriv, "bbbb", "aaaa", aPub, w1); err == nil {
		t.Fatal("a handshake signed by the wrong key was accepted")
	}
}

func TestSessionKeysDifferPerHandshake(t *testing.T) {
	a1, _ := establish(t)
	_, b2 := establish(t)

	ct, err := a1.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// b2 was part of a different handshake, so it must not be able to read it.
	if _, err := b2.Open(ct); err == nil {
		t.Fatal("a session from another handshake decrypted the message")
	}
}
