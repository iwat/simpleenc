package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var decCmd = &cobra.Command{
	Use:   "dec [file to decrypt]",
	Short: "Decrypt an encrypted content from file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pwd := readPass()
		defer func() { cleanByteSlice(pwd) }()

		fd, err := os.Open(args[0])
		checkError(err)

		in := decodeCipherPayload(fd)
		dk := deriveKey(pwd, in.Salt)
		aesgcm := newCipher(dk)
		//cleanByteSlice(dk)

		ciphertext := in.CipherText

		fmt.Fprintf(os.Stderr, "salt:  %x\n", in.Salt)
		fmt.Fprintf(os.Stderr, "key:   %x\n", shake(dk))
		fmt.Fprintf(os.Stderr, "nonce: %x\n", in.Nonce)

		dst, err := aesgcm.Open(nil, in.Nonce, ciphertext, nil)
		checkError(err)

		os.Stdout.Write(dst)
	},
}

func init() {
	rootCmd.AddCommand(decCmd)
}

func readFile(fd io.Reader, size int, label string) []byte {
	data := make([]byte, size)
	n, err := fd.Read(data)
	checkError(err)
	if n != size {
		panic(label + " missing")
	}
	return data
}
