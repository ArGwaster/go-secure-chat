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

	pubB64, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Erreur lecture clé publique :", err)
	}
	pubBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		log.Fatal(err)
	}

	pub, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		log.Fatal("Erreur : clé publique incorrecte")
	}

	sessionKey := generateSessionKey()
	encKey := encryptSessionKey(pub, sessionKey)
	writer.WriteString(base64.StdEncoding.EncodeToString(encKey) + "\n")
	writer.Flush()

	fmt.Println("🔐 Session sécurisée établie.")

	go readLoop(reader, sessionKey)
	writeLoop(writer, sessionKey)
}
