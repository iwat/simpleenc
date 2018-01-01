package cmd

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

const (
	scryptN = 32768
	scryptR = 8
	scryptP = 1
)

var encCmd = &cobra.Command{
	Use:   "enc",
	Short: "Encrypt a plain text to STDOUT",
	Run: func(cmd *cobra.Command, args []string) {
		pwd := readPass()
		defer func() { cleanByteSlice(pwd) }()

		salt := readRand(32, "salt")
		dk := deriveKey(pwd, salt, scryptN, scryptR, scryptP, keyLenAES256)
		aesgcm := newCipher(dk)
		//cleanByteSlice(dk)

		nonce := readRand(aesgcm.NonceSize(), "nonce")

		plaintext, err := ioutil.ReadAll(os.Stdin)
		checkError(err)

		ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
		cleanByteSlice(plaintext)

		fmt.Fprintf(os.Stderr, "salt:  %x\n", salt)
		fmt.Fprintf(os.Stderr, "key:   %x\n", shake(dk))
		fmt.Fprintf(os.Stderr, "nonce: %x\n", nonce)

		out := cipherPayload{algoName, scryptPayload{salt, scryptN, scryptR, scryptP}, nonce, ciphertext}
		out.encode(os.Stdout)
	},
}

func init() {
	rootCmd.AddCommand(encCmd)
}

func readRand(size int, label string) []byte {
	data := make([]byte, size)
	n, err := rand.Read(data)
	checkError(err)
	if n != size {
		panic("read " + label + " failed")
	}
	return data
}
