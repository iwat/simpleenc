package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"

	"github.com/howeyc/gopass"
)

type b64 []byte

func (b b64) MarshalJSON() ([]byte, error) {
	enc := base64.StdEncoding.EncodeToString(b)
	return []byte("\"" + enc + "\""), nil
}

func (b *b64) UnmarshalJSON(s []byte) error {
	dec, err := base64.StdEncoding.DecodeString(string(s[1 : len(s)-1]))
	*b = dec
	return err
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

type cipherB64 struct {
	Salt       b64
	Nonce      b64
	CipherText b64
}

type cipherPayload struct {
	Salt       []byte
	Nonce      []byte
	CipherText []byte
}

func decodeCipherPayload(r io.Reader) cipherPayload {
	b := cipherB64{}
	dec := json.NewDecoder(r)
	err := dec.Decode(&b)
	checkError(err)
	return cipherPayload{b.Salt, b.Nonce, b.CipherText}
}

func (p cipherPayload) encode(w io.Writer) {
	b := cipherB64{p.Salt, p.Nonce, p.CipherText}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err := enc.Encode(b)
	checkError(err)
}

func cleanByteSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func deriveKey(pwd, salt []byte) []byte {
	dk, err := scrypt.Key(pwd, salt, 32768, 8, 1, 32)
	checkError(err)

	return dk
}

func newCipher(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	checkError(err)

	aesgcm, err := cipher.NewGCM(block)
	checkError(err)

	return aesgcm
}

func readPass() []byte {
	pwd, err := gopass.GetPasswdPrompt("Enter passphrase:", true, os.Stdin, os.Stderr)
	checkError(err)

	return pwd
}

func shake(dk []byte) []byte {
	ret := make([]byte, 32)
	sha3.ShakeSum256(ret, dk)
	return ret
}
