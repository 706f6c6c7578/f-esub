package main

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/sha3"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type esub struct {
	key     string
	subject string
}

var (
	rcFlag     = flag.Bool("rc", false, "enable replay cache to prevent processing duplicate esubs")
	dbPath     = flag.String("dbpath", "", "custom path for the replay cache database (default: $HOME/.esub_rc.db)")
	db         *sql.DB
	dbInitErr  error
	replayCache = make(map[string]bool)
)

func initDB() {
	if !*rcFlag {
		return
	}

	path := *dbPath
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			dbInitErr = fmt.Errorf("failed to get user home directory: %v", err)
			return
		}
		path = filepath.Join(homeDir, ".esub_rc.db")
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			dbInitErr = fmt.Errorf("failed to create database directory: %v", err)
			return
		}
	}

	var err error
	db, err = sql.Open("sqlite3", path)
	if err != nil {
		dbInitErr = fmt.Errorf("failed to open database: %v", err)
		return
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS esubs (
		esub_hex TEXT PRIMARY KEY,
		first_seen TEXT NOT NULL
	)`)
	if err != nil {
		dbInitErr = fmt.Errorf("failed to create table: %v", err)
		return
	}

	rows, err := db.Query("SELECT esub_hex FROM esubs")
	if err != nil {
		dbInitErr = fmt.Errorf("failed to query existing esubs: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var esubHex string
		if err := rows.Scan(&esubHex); err != nil {
			dbInitErr = fmt.Errorf("failed to scan esub: %v", err)
			return
		}
		replayCache[esubHex] = true
	}
}

func (e *esub) checkReplayCache() bool {
	if !*rcFlag || dbInitErr != nil {
		return false
	}

	if _, exists := replayCache[e.subject]; exists {
		return true
	}

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM esubs WHERE esub_hex = ?", e.subject).Scan(&count)
	if err != nil {
		fmt.Printf("Warning: failed to check replay cache: %v\n", err)
		return false
	}
	return count > 0
}

func (e *esub) addToReplayCache() error {
	if !*rcFlag || dbInitErr != nil {
		return nil
	}

	if e.checkReplayCache() {
		return nil
	}

	_, err := db.Exec("INSERT INTO esubs (esub_hex, first_seen) VALUES (?, ?)",
		e.subject, time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to insert esub into replay cache: %v", err)
	}

	replayCache[e.subject] = true
	return nil
}

func (e *esub) esubtest() bool {
	if len(e.subject) != 48 {
		return false
	}

	if e.checkReplayCache() {
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

	if hex.EncodeToString(expectedCiphertext) == hex.EncodeToString(receivedCiphertext) {
		if err := e.addToReplayCache(); err != nil {
			fmt.Printf("Warning: failed to cache esub: %v\n", err)
		}
		return true
	}
	return false
}

func (e *esub) deriveKey() []byte {
	salt := []byte("fixed-salt-1234")
	return argon2.IDKey(
		[]byte(e.key),
		salt,
		3,
		64*1024,
		4,
		32,
	)
}

func findValidSubjectsInFile(filename string, key string) {
	if dbInitErr != nil {
		fmt.Printf("Warning: replay cache disabled due to error: %v\n", dbInitErr)
	}

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
		initDB()
		findValidSubjectsInFile(cmdargs[0], cmdargs[1])
		if db != nil {
			db.Close()
		}
	default:
		fmt.Println("Usage: f-esub [-rc] [-dbpath /custom/path.db] <filename> <key>")
		os.Exit(2)
	}
}