package encoding

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	pvktype = "RSA PRIVATE KEY"
	pbktype = "RSA PUBLIC KEY"
	size    = 2048
)

func TestReader(t *testing.T) {
	s := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tt := []struct {
		name   string
		reader *Reader
		result string
	}{
		{"rot13", NewRot13Reader(strings.NewReader(s)), "NOPQRSTUVWXYZABCDEFGHIJKLM"},
		{"atbash", NewAtBashReader(strings.NewReader(s)), "ZYXWVUTSRQPONMLKJIHGFEDCBA"},
		{"rot13 + atbash", NewAtBashReader(NewRot13Reader(strings.NewReader(s))), "MLKJIHGFEDCBAZYXWVUTSRQPON"},
		{"atbash + rot13", NewRot13Reader(NewAtBashReader(strings.NewReader(s))), "MLKJIHGFEDCBAZYXWVUTSRQPON"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, len(s))
			_, err := io.ReadFull(tc.reader, b)
			if err != nil {
				t.Errorf("cannot read from reader to buffer : %v\n", err)
			}

			ds := string(b)

			if tc.result != ds {
				t.Errorf("%s should be encoded as %s and not %s", s, tc.result, ds)
			}
		})
	}

}

type eofReader struct{}

func (eofReader) Read(p []byte) (n int, err error) {
	err = io.EOF
	return
}

type errFooReader struct{}

var errFoo = errors.New("ERRFOO")

func (errFooReader) Read(p []byte) (n int, err error) {
	err = errFoo
	return
}

func TestReaderWithError(t *testing.T) {

	tt := []struct {
		name string
		r    *Reader
		e    error
	}{
		{"EOF", &Reader{reader: &eofReader{}}, io.EOF},
		{"ERRFOO", &Reader{reader: &errFooReader{}}, errFoo},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, 1)
			n, err := io.ReadFull(tc.r, b)

			if !errors.Is(err, tc.e) {
				t.Errorf("want %v, got %v", tc.e, err)
			}

			if n != 0 {
				t.Errorf("no bit should have been read : bits read = %v", n)
			}
		})
	}

}

func TestRSA(t *testing.T) {
	rng := rand.Reader

	pvk, err := rsa.GenerateKey(rng, size)
	if err != nil {
		t.Errorf("can not generate RSA Keys : %w", err)
	}

	pbk := pvk.PublicKey

	label := []byte("lebal")

	h := sha256.New()

	secret := "TRENDev rules"
	msgbytes := []byte(secret)

	// encrypts the secret message
	ebytes, err := rsa.EncryptOAEP(
		h,
		rng,
		&pbk,
		msgbytes,
		label)

	if err != nil {
		if errors.Is(err, rsa.ErrMessageTooLong) {
			t.Fatalf("can not encrypt : %v", err)
		} else {
			t.Fatalf("can not encrypt %q : %v", secret, err)
		}
	}

	// decrypts the secret message
	dbytes, err := rsa.DecryptOAEP(
		h,
		rng,
		pvk,
		ebytes,
		label)
	if err != nil {
		t.Fatalf("can not decrypt encrypted message : %v", err)
	}

	if bytes.Compare(dbytes, msgbytes) != 0 {
		t.Fatalf("can not decrypt encrypted message : want %q, get %q", secret, string(dbytes))
	}

	// encrypts the decrypted message
	ebytes2, err := rsa.EncryptOAEP(
		h,
		rng,
		&pbk,
		dbytes,
		label)

	if err != nil {
		if errors.Is(err, rsa.ErrMessageTooLong) {
			t.Fatalf("can not encrypt : %v", err)
		} else {
			t.Fatalf("can not encrypt %q : %v", string(dbytes), err)
		}
	}

	if bytes.Compare(ebytes, ebytes2) == 0 {
		t.Fatalf("re-encryption should not provide the same encrypted bytes")
	}

	// decrypts the re-encrypted message
	dbytes2, err := rsa.DecryptOAEP(
		h,
		rng,
		pvk,
		ebytes2,
		label)
	if err != nil {
		t.Fatalf("can not decrypt encrypted message : %v", err)
	}

	if bytes.Compare(dbytes, dbytes2) != 0 {
		t.Fatalf("decryption of re-encrypted messageand decryped message should be equal")
	}

}

func TestRSAKeys(t *testing.T) {
	rng := rand.Reader

	pvk, err := rsa.GenerateKey(rng, size)
	if err != nil {
		t.Errorf("can not generate RSA Keys : %w", err)
	}

	pbk := pvk.PublicKey

	var pvkbuf, pbkbuf bytes.Buffer

	if err := pem.Encode(&pvkbuf, &pem.Block{Type: pvktype, Bytes: x509.MarshalPKCS1PrivateKey(pvk)}); err != nil {
		t.Fatalf("can not encode rsa private key in buffer : %v", err)
	}

	// display rsa private key
	// io.Copy(os.Stdout, &pvkbuf)

	if err := pem.Encode(&pbkbuf, &pem.Block{Type: pbktype, Bytes: x509.MarshalPKCS1PublicKey(&pbk)}); err != nil {
		t.Fatalf("can not encode rsa public key in buffer : %v", err)
	}

	// display rsa public key
	// io.Copy(os.Stdout, &pbkbuf)

	pvkblock, _ := pem.Decode(pvkbuf.Bytes())
	if pvkblock == nil || pvkblock.Type != pvktype || pvkblock.Bytes == nil {
		t.Fatalf("can not decode rsa private key from buffer")
	}

	// loads and controls rsa private key
	pvk2, err := x509.ParsePKCS1PrivateKey(pvkblock.Bytes)
	if err != nil {
		t.Fatalf("can not find valid rsa private key in pem block : %v ", err)
	}

	if !pvk.Equal(pvk2) {
		t.Fatalf("loaded key should be equal to original rsa private key")
	}

	// loads and controls rsa public key
	pbkblock, _ := pem.Decode(pbkbuf.Bytes())
	if pbkblock == nil || pbkblock.Type != pbktype || pbkblock.Bytes == nil {
		t.Fatalf("can not decode rsa public key from buffer")
	}

	pbk2, err := x509.ParsePKCS1PublicKey(pbkblock.Bytes)
	if err != nil {
		t.Fatalf("can not find valid rsa public key in pem block : %v ", err)
	}

	if !pbk.Equal(pbk2) {
		t.Fatalf("loaded rsa public key should be equal to original rsa public key")
	}

	// just for fun (or funk...)
	if !pvk.PublicKey.Equal(pbk2) {
		t.Fatalf("loaded rsa public key should be equal to original rsa public in original private key")
	}
}
