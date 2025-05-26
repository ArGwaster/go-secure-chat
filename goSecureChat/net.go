package goSecureChat

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
)

func readLoopJSON(reader *bufio.Reader, sessionKey []byte) {
	for {
		jsonLine, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal("Erreur lecture message JSON :", err)
		}

		encMsg, err := parseEncryptedMessage([]byte(strings.TrimSpace(jsonLine)))
		if err != nil {
			fmt.Println("❌ Erreur parsing message :", err)
			continue
		}

		if encMsg.Type != TypeMessage {
			fmt.Printf("⚠️ Type de message inattendu : %s\n", encMsg.Type)
			continue
		}

		nonce, err := base64.StdEncoding.DecodeString(encMsg.Nonce)
		if err != nil {
			fmt.Println("❌ Erreur décodage nonce :", err)
			continue
		}

		ct, err := base64.StdEncoding.DecodeString(encMsg.Ciphertext)
		if err != nil {
			fmt.Println("❌ Erreur décodage ciphertext :", err)
			continue
		}

		msg := decryptMessage(sessionKey, ct, nonce)
		fmt.Println("\n📩 Reçu :", msg)
		fmt.Print("→ ")
	}
}

func writeLoopJSON(writer *bufio.Writer, sessionKey []byte) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("→ ")
		scanner.Scan()
		msg := scanner.Text()

		ct, nonce := encryptMessage(sessionKey, msg)
		ctB64 := base64.StdEncoding.EncodeToString(ct)
		nonceB64 := base64.StdEncoding.EncodeToString(nonce)

		encMsg, err := createEncryptedMessage(ctB64, nonceB64)
		if err != nil {
			fmt.Println("❌ Erreur création message :", err)
			continue
		}

		writer.WriteString(string(encMsg) + "\n")
		writer.Flush()
	}
}
