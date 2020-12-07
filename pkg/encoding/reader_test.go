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
	"os"
	"strings"
	"testing"
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

func TestRSAEncryption(t *testing.T) {
	rng := rand.Reader

	pvk, err := rsa.GenerateKey(rng, 2048)
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

func TestStoreRSAKeys(t *testing.T) {
	rng := rand.Reader

	pvk, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Errorf("can not generate RSA Keys : %w", err)
	}

	pbk := pvk.PublicKey

	var pvkbuf, pbkbuf bytes.Buffer

	if err := pem.Encode(&pvkbuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pvk)}); err != nil {
		t.Fatalf("can not encode rsa private key in buffer : %v", err)
	}

	io.Copy(os.Stdout, &pvkbuf)

	if err := pem.Encode(&pbkbuf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&pbk)}); err != nil {
		t.Fatalf("can not encode rsa public key in buffer : %v", err)
	}

	io.Copy(os.Stdout, &pbkbuf)
}
