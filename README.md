# File Encryption CLI

This is a simple command-line interface (CLI) tool written in Go for encrypting and decrypting files. It uses a password-based encryption scheme.

## Installation

To install this tool, you need to have Go installed on your machine. Once you have Go installed, you can clone this repository and build the tool using the following commands:

```bash
git clone https://github.com/akashdeep-patra/go-file-encryption.git
cd go-file-encryption
go build -o file-encryption
```

## Usage

This tool supports three commands: `encrypt`, `decrypt`, and `help`.

### Encrypt

To encrypt a file, use the `encrypt` command followed by the path to the file you want to encrypt:

```bash
./file-encryption encrypt /path/to/file
```

You will be prompted to enter a password for the encryption. The password should be at least 8 characters long, contain at least one number, and at least one special character. You will need to confirm the password by entering it again.

### Decrypt

To decrypt a file, use the `decrypt` command followed by the path to the file you want to decrypt:

```bash
./file-encryption decrypt /path/to/file
```

You will be prompted to enter the password that was used to encrypt the file.

### Help

To display a help message, use the `help` command:

```bash
./file-encryption help
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.