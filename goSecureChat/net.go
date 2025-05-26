package goSecureChat

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
)

func readLoop(reader *bufio.Reader, sessionKey []byte) {
	for {
		nonceB64, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal("Erreur lecture nonce :", err)
		}
		ctB64, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal("Erreur lecture ciphertext :", err)
		}

		nonce, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(nonceB64))
		ct, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(ctB64))

		msg := decryptMessage(sessionKey, ct, nonce)
		fmt.Println("\n📩 Reçu :", msg)
		fmt.Print("→ ")
	}
}

func writeLoop(writer *bufio.Writer, sessionKey []byte) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("→ ")
		scanner.Scan()
		msg := scanner.Text()

		ct, nonce := encryptMessage(sessionKey, msg)
		writer.WriteString(base64.StdEncoding.EncodeToString(nonce) + "\n")
		writer.WriteString(base64.StdEncoding.EncodeToString(ct) + "\n")
		writer.Flush()
	}
}
