package main

import (
	"github.com/akashdeep-patra/go-file-encryption/utils"
	"golang.org/x/term"
	"os"
	"strings"
)

type OperationName string

const (
	ENCRYPT OperationName = "ENCRYPT"
	DECRYPT OperationName = "DECRYPT"
	HELP    OperationName = "HELP"
)

func printHelp() {
	println("File encryption and decryption tool")
	println("Simple file encryption and decryption tool for your day to day use.")
	println("Usage:")
	println("")
	println("\t go run . encrypt /path/to/file")
	println("")
	println("Commands:")
	println("")
	println("\t encrypt\tEncrypts a file given a password")
	println("\t decrypt\ttries to Decrypt a file given a password")
	println("\t help\t\tPrints this help message")
	println("")

}
func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	operation := os.Args[1]
	switch operation {
	case "help":
		printHelp()
	case "encrypt":
		encryptFileHandler()

	case "decrypt":
		decryptFileHandler()
	default:
		println("Run encrypt to encrypt a file or decrypt to decrypt a file.")
		os.Exit(1)

	}
}

func encryptFileHandler() {
	if len(os.Args) < 3 {
		println("Please provide the path to a file to encrypt")
		os.Exit(0)
	}
	filePath := os.Args[2]
	if !validateFile(filePath) {
		os.Exit(0)
	}
	password := getPassword(ENCRYPT)
	println("Encrypting file...")
	encryption.EncryptFile(filePath, password)
	println("File encrypted successfully")
}

func decryptFileHandler() {
	if len(os.Args) < 3 {
		println("Please provide the path to a file to decrypt")
		os.Exit(0)
	}
	filePath := os.Args[2]
	if !validateFile(filePath) {
		os.Exit(0)
	}
	password := getPassword(DECRYPT)
	println("Decrypting file...")
	encryption.DecryptFile(filePath, password)
	println("File decrypted successfully")
}

func validatePassword(passwordByte []byte, confirmPasswordByte []byte) bool {
	password := string(passwordByte)
	confirmPassword := string(confirmPasswordByte)
	// check the length of the password, should be at least 8 characters
	if len(password) < 8 {
		println("Password should be at least 8 characters")
		return false
	}
	// check if it has at least one number
	if !strings.ContainsAny(password, "0123456789") {
		println("Password should contain at least one number")
		return false
	}
	//check if it has at least one special character
	if !strings.ContainsAny(password, "!@#$%^&*()_+-=") {
		println("Password should contain at least one special character")
		return false
	}
	// check if the password and confirm password match
	if password != confirmPassword {
		println("Passwords do not match")
		return false
	}
	return true

}
func getPassword(operationType OperationName) []byte {
	switch operationType {
	case ENCRYPT:
		println("Enter a password to encrypt the file")
	case DECRYPT:
		println("Enter the password to decrypt the file")
	}
	password, err := term.ReadPassword(0)

	if err != nil {
		panic(err)
	}
	if operationType == ENCRYPT {
		println("Confirm password")
		confirmPassword, err := term.ReadPassword(0)
		if err != nil {
			panic(err)
		}
		if !validatePassword(password, confirmPassword) {
			os.Exit(0)
		}
	}
	return password
}

func validateFile(filepath string) bool {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		println("Invalid file/path path")
		return false
	}

	return true
}
