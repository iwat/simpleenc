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

const keyLenAES256 = 32
const algoName = "SCRYPT-AES-256-GCM"

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
	Algo       string
	Scrypt     scryptB64
	Nonce      b64
	CipherText b64
}

type cipherPayload struct {
	Algo       string
	Scrypt     scryptPayload
	Nonce      []byte
	CipherText []byte
}

func decodeCipherPayload(r io.Reader) cipherPayload {
	b := cipherB64{}
	dec := json.NewDecoder(r)
	err := dec.Decode(&b)
	checkError(err)
	return cipherPayload{b.Algo, scryptPayload{b.Scrypt.Salt, b.Scrypt.N, b.Scrypt.R, b.Scrypt.P}, b.Nonce, b.CipherText}
}

func (p cipherPayload) encode(w io.Writer) {
	b := cipherB64{p.Algo, scryptB64{p.Scrypt.Salt, p.Scrypt.N, p.Scrypt.R, p.Scrypt.P}, p.Nonce, p.CipherText}
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

func deriveKey(pwd, salt []byte, N, r, p, keyLen int) []byte {
	dk, err := scrypt.Key(pwd, salt, N, r, p, keyLen)
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

type scryptB64 struct {
	Salt b64
	N    int
	R    int
	P    int
}

type scryptPayload struct {
	Salt []byte
	N    int
	R    int
	P    int
}

func shake(dk []byte) []byte {
	ret := make([]byte, 32)
	sha3.ShakeSum256(ret, dk)
	return ret
}
