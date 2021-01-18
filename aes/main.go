package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
)

type messageData struct {
	message string
	key     string
}

type response struct {
	statusCode       uint8
	message          string
	encryptedMessage string
}

// Run runs the module
func Run(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	msgData := messageData{
		message: r.FormValue("message"),
		key:     r.FormValue("key"),
	}

	iv, blk, err := createVector([]byte(msgData.key))
	if err != nil {
		log.Fatalln(err)
	}

	encData := msgData.encryptMessage(blk, iv)
	encMessage := []byte(fmt.Sprintf("ENCRYPTED: %s\nMESSAGE: %s\nCODE: %d\n",
		encData.encryptedMessage, encData.message, encData.statusCode))

	if _, err = w.Write(encMessage); err != nil {
		log.Println("error writing encrypted", err)
	}

	rdr := bytes.NewReader([]byte(encData.encryptedMessage))

	encReader, err := encryptReader(rdr, blk, iv)
	if err != nil {
		log.Fatalln(err)
	}

	if _, err = io.Copy(w, encReader); err != nil {
		log.Fatalln(err)
	}
}

func (msgData *messageData) encryptMessage(blk cipher.Block, iv []byte) *response {
	wtr := &bytes.Buffer{}
	encWriter, err := encryptWriter(wtr, blk, iv)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.WriteString(encWriter, msgData.message)
	if err != nil {
		log.Fatalln(err)
	}

	return &response{
		statusCode:       http.StatusOK,
		message:          "Encryption Successful",
		encryptedMessage: wtr.String(),
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
	cipherKey, err := createKey(string(key))
	if err != nil {
		log.Fatalln(err)
	}

	b, err := aes.NewCipher(cipherKey)
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
