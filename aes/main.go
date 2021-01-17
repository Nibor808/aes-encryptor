package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func Run(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	msg := "The message coming in from the form"

	key, err := createKey("ilovedogs")
	if err != nil {
		log.Fatalln(err)
	}

	iv, blk, err := createVector(key)
	if err != nil {
		log.Fatalln(err)
	}

	wtr := &bytes.Buffer{}
	encWriter, err := encryptWriter(wtr, blk, iv)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.WriteString(encWriter, msg)
	if err != nil {
		log.Fatalln(err)
	}

	encrypted := wtr.String()

	fmt.Println("ENCODED WITH AES:", encrypted)

	rdr := bytes.NewReader([]byte(encrypted))

	encReader, err := encryptReader(rdr, blk, iv)
	if err != nil {
		log.Fatalln(err)
	}

	if _, err = io.Copy(os.Stdout, encReader); err != nil {
		log.Fatalln(err)
	}
}

// encryptWriter creates a wrapper around a writer
// and returns an encrypted writer
func encryptWriter(wtr io.Writer, blk cipher.Block, iv []byte) (io.Writer, error) {
	s := cipher.NewCTR(blk, iv)

	return cipher.StreamWriter{
		S: s,
		W: wtr,
	}, nil
}

// encryptReader creates a wrapper around a reader
// and returns an encrypted reader
func encryptReader(r io.Reader, blk cipher.Block, iv []byte) (io.Reader, error) {
	s := cipher.NewCTR(blk, iv)

	return &cipher.StreamReader{
		S: s,
		R: r,
	}, nil
}

// createKey returns a 16 byte key
// for use in createVector
func createKey(str string) ([]byte, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.MinCost)
	if err != nil {
		return nil, fmt.Errorf("couldn't bcrypt string: %w", err)
	}

	// AES encoding takes a key of defined size either 16, 24, or 32 bytes
	// here we create the key by taking the first 16 bytes of a bcrypt encoded string
	return b[:16], nil
}

// createVector returns a newly created initialization vector
// and the cipher.Block to be passed to encryptWriter and encryptReader
func createVector(key []byte) ([]byte, cipher.Block, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting new cipher: %w", err)
	}

	// initialization vector (similar to a salt)
	iv := make([]byte, aes.BlockSize)

	// to add more randomness - io.ReadFull(rand.Reader, iv)
	// to fill byte slice with random numbers instead of just "0"'s
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalln(err)
	}

	return iv, b, nil
}