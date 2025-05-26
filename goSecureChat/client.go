package goSecureChat

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
)

func ClientMode(address string) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// 1. Recevoir la clé publique via JSON
	jsonLine, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Erreur lecture message JSON :", err)
	}

	msg, err := parseProtocolMessage([]byte(strings.TrimSpace(jsonLine)))
	if err != nil {
		log.Fatal("Erreur parsing JSON :", err)
	}

	if msg.Type != TypeHandshake {
		log.Fatal("Type de message inattendu :", msg.Type)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		log.Fatal("Erreur décodage clé publique :", err)
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		log.Fatal(err)
	}

	pub, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		log.Fatal("Erreur : clé publique incorrecte")
	}

	// 2. Générer et envoyer la clé de session via JSON
	sessionKey := generateSessionKey()
	encKey := encryptSessionKey(pub, sessionKey)
	encKeyB64 := base64.StdEncoding.EncodeToString(encKey)

	sessionKeyMsg, err := createSessionKeyMessage(encKeyB64)
	if err != nil {
		log.Fatal(err)
	}
	writer.WriteString(string(sessionKeyMsg) + "\n")
	writer.Flush()

	fmt.Println("🔐 Session sécurisée établie.")

	go readLoopJSON(reader, sessionKey)
	writeLoopJSON(writer, sessionKey)
}
