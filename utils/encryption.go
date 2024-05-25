package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func handleErr(err error) {
	if err != nil {
		panic(err.Error())
	}

}
func EncryptFile(filePath string, password []byte) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		handleErr(err)
	}
	file, err := os.Open(filePath)
	handleErr(err)
	defer file.Close()
	plainText, err := io.ReadAll(file)
	handleErr(err)
	key := password
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	handleErr(err)
	derivedKey := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(derivedKey)
	handleErr(err)

	aesCipherHead, err := cipher.NewGCM(block)
	handleErr(err)
	cipherText := aesCipherHead.Seal(nil, nonce, plainText, nil)
	cipherText = append(cipherText, nonce...)

	destinationFile, err := os.Create(filePath)
	handleErr(err)
	defer destinationFile.Close()
	_, err = destinationFile.Write(cipherText)
	handleErr(err)

}

func DecryptFile(filePath string, password []byte) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		handleErr(err)
	}
	file, err := os.Open(filePath)
	handleErr(err)
	defer file.Close()
	cipherText, err := io.ReadAll(file)
	handleErr(err)

	key := password
	salt := cipherText[len(cipherText)-12:]
	str := hex.EncodeToString(salt)
	monce, err := hex.DecodeString(str)
	handleErr(err)

	derivedKey := pbkdf2.Key(key, monce, 4096, 32, sha1.New)
	block, err := aes.NewCipher(derivedKey)
	handleErr(err)
	aesCipherHead, err := cipher.NewGCM(block)
	handleErr(err)
	plainText, err := aesCipherHead.Open(nil, monce, cipherText[:len(cipherText)-12], nil)
	handleErr(err)
	destinationFile, err := os.Create(filePath)
	handleErr(err)
	defer destinationFile.Close()
	_, err = destinationFile.Write(plainText)
	handleErr(err)

}
