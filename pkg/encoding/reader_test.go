package encoding

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
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
		t.Errorf("can not generate RSA Keys : %v", err)
		t.FailNow()
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

	if !bytes.Equal(dbytes, msgbytes) {
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
	if bytes.Equal(ebytes, ebytes2) {
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

	if !bytes.Equal(dbytes, dbytes2) {
		t.Fatalf("decryption of re-encrypted messageand decryped message should be equal")
	}

}

func TestRSAKeys(t *testing.T) {
	rng := rand.Reader

	pvk, err := rsa.GenerateKey(rng, size)
	if err != nil {
		t.Errorf("can not generate RSA Keys : %v", err)
		t.Failed()
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

	// just for fun
	if !pvk.PublicKey.Equal(pbk2) {
		t.Fatalf("loaded rsa public key should be equal to original rsa public in original private key")
	}
}

func TestECDSASignature(t *testing.T) {
	rng := rand.Reader
	// same strength as RSA 15306 : strong enough ;)
	pvk, err := ecdsa.GenerateKey(elliptic.P521(), rng)
	if err != nil {
		t.Fatalf("cannot generate ECDSA private key : %v ", err)
	}

	msg := "TRENDev rules"
	b := []byte(msg)

	h1 := sha512.Sum512_224(b)
	h2 := sha256.Sum256(b)
	h3 := sha256.Sum224(b)
	h4 := sha3.Sum512(b)
	_ = h4
	tt := []struct {
		name string
		h    []byte
	}{
		{"SHA512-224", h1[:]},
		{"SHA256", h2[:]},
		{"SHA224", h3[:]},
		{"SHA3-512", h4[:]},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			s, err := ecdsa.SignASN1(rng, pvk, tc.h)
			if err != nil {
				t.Fatalf("cannot sign %q : %v ", msg, err)
			}

			t.Logf("ECDSA-%v signature = %x", tc.name, s)

			if ok := ecdsa.VerifyASN1(&pvk.PublicKey, tc.h, s); !ok {
				t.Fatalf("ECDSA-%v : signature %x is INVALID ", tc.name, s)
			}
		})
	}

}

func TestAtBash(t *testing.T) {
	tt := []struct {
		b, r byte
	}{
		{'a', 'z'},
		{'z', 'a'},
		{'b', 'y'},
		{'y', 'b'},
		{'f', 'u'},
		{'k', 'p'},
		{'m', 'n'},
		{'K', 'P'},
		{'M', 'N'},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%c", tc.b), func(t *testing.T) {
			got := atbash(tc.b)
			if got != tc.r {
				t.Errorf("atbash(%c) == %c, got %c", tc.b, tc.r, got)
				t.FailNow()
			}
		})
	}
}

func TestRot13(t *testing.T) {
	tt := []struct {
		b, r byte
	}{
		{'a', 'n'},
		{'z', 'm'},
		{'b', 'o'},
		{'y', 'l'},
		{'f', 's'},
		{'k', 'x'},
		{'m', 'z'},
		{'M', 'Z'},
		{'A', 'N'},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%c", tc.b), func(t *testing.T) {
			got := rot13(tc.b)
			if got != tc.r {
				t.Errorf("rot13(%c) == %c, got %c", tc.b, tc.r, got)
				t.FailNow()
			}
		})
	}
}
