package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/blowfish"
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

	esub, err := hex.DecodeString(e.subject)
	if err != nil {
		return false
	}

	iv := esub[:8]
	textHash := md5.Sum([]byte("text"))
	keyHash := md5.Sum([]byte(e.key))

	block, err := blowfish.NewCipher(keyHash[:])
	if err != nil {
		return false
	}

	stream1 := cipher.NewOFB(block, iv)
	crypt1 := make([]byte, 8)
	stream1.XORKeyStream(crypt1, textHash[:8])

	stream2 := cipher.NewOFB(block, crypt1)
	crypt2 := make([]byte, 8)
	stream2.XORKeyStream(crypt2, textHash[8:16])

	result := make([]byte, 0, 24)
	result = append(result, iv...)
	result = append(result, crypt1...)
	result = append(result, crypt2...)

	newesub := hex.EncodeToString(result)
	return newesub == e.subject
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
