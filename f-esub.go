package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
        "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/sha3"
	"os"
	"strings"
)

type esub struct {
	key     string
	subject string
}

func (e *esub) esubtest() bool {
	if len(e.subject) != 48 {
		return false
	}

	esubBytes, err := hex.DecodeString(e.subject)
	if err != nil || len(esubBytes) != 24 {
		return false
	}

	nonce := esubBytes[:12]
	receivedCiphertext := esubBytes[12:]

	key := e.deriveKey()
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return false
	}

	textHash := sha3.Sum256([]byte("text"))
	expectedCiphertext := make([]byte, 12)
	cipher.XORKeyStream(expectedCiphertext, textHash[:12])

	return hex.EncodeToString(expectedCiphertext) == hex.EncodeToString(receivedCiphertext)
}

func (e *esub) deriveKey() []byte {
	// Argon2id parameters (adjust time/memory/threads as needed)
	salt := []byte("fixed-salt-1234") // Use a unique, constant salt (or randomize & store it)
	key := argon2.IDKey(
		[]byte(e.key),
		salt,
		3,      // iterations
		64*1024, // 64MB memory
		4,      // threads
		32,     // output key length (32 bytes for ChaCha20)
	)
	return key
}

func findValidSubjectsInFile(filename string, key string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}
	defer file.Close()

	var outputFile *os.File
	var headers []string
	scanner := bufio.NewScanner(file)

Loop:
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ".") {
			if outputFile != nil {
				outputFile.Close()
				outputFile = nil
			}
			headers = nil
			continue Loop
		}

		var parts []string
		if strings.Contains(line, "Subject:") {
			parts = strings.Split(line, "Subject:")
		} else if strings.Contains(line, "X-Esub:") {
			parts = strings.Split(line, "X-Esub:")
		}

		if len(parts) > 1 {
			e := &esub{key: key, subject: strings.TrimSpace(parts[1])}
			if len(e.subject) == 48 {
				if e.esubtest() {
					if outputFile != nil {
						outputFile.Close()
					}
					outputFileName := fmt.Sprintf("valid_esub_%s.txt", e.subject)
					outputFile, err = os.Create(outputFileName)
					if err != nil {
						fmt.Println("Error creating output file:", err)
						os.Exit(1)
					}
					fmt.Println("Valid esub:", e.subject)
					for _, header := range headers {
						fmt.Fprintln(outputFile, header)
					}
					headers = nil
				} else {
					continue
				}
			}
		}

		if outputFile != nil {
			fmt.Fprintln(outputFile, line)
		} else {
			headers = append(headers, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	if outputFile != nil {
		outputFile.Close()
	}
}

func main() {
	flag.Parse()
	cmdargs := flag.Args()
	switch len(cmdargs) {
	case 2:
		findValidSubjectsInFile(cmdargs[0], cmdargs[1])
	default:
		fmt.Println("Usage: f-esub <filename> <key>")
		os.Exit(2)
	}
}
